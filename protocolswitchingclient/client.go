package protocolswitchingclient

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

const (
	// StateUnknown when we don't currently know if server will support http or http3
	StateUnknown = iota // 0
	// StateHttp server is currently known to support http
	StateHttp // 1
	// StateHttp3 server is currently known to support http3
	StateHttp3 // 2
)

// HttpState one of the 'enum' values above
type HttpState int

// DynamicClient holds the state and client for a client connection
type DynamicClient struct {
	mux              sync.RWMutex
	desiredHttpState HttpState
	httpState        HttpState
	timeToLive       time.Duration
	connectionStart  time.Time
	http3Client      *http.Client
	fallbackClient   *http.Client
}

func NewDynamicClient(transport http.RoundTripper, jar *cookiejar.Jar, DesiredHttp HttpState, TTL time.Duration) *DynamicClient {
	insecureSkipVerify := false
	if p, ok := transport.(*http.Transport); ok && p.TLSClientConfig != nil {
		insecureSkipVerify = p.TLSClientConfig.InsecureSkipVerify
	}

	http3Transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify, // For local dev/self-signed certs
			MinVersion:         tls.VersionTLS13,
		},
	}

	// Create HTTP client using the HTTP/3 transport
	http3Client := &http.Client{
		Transport: http3Transport,
		Timeout:   10 * time.Second,
	}
	if jar != nil {
		// Create HTTP client using the HTTP/2 transport
		http3Client = &http.Client{
			Transport: http3Transport,
			Timeout:   10 * time.Second,
			Jar:       jar,
		}
	}

	fallbackClient := &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second,
	}
	if jar != nil {
		// Create HTTP client using the HTTP/2 transport
		fallbackClient = &http.Client{
			Transport: transport,
			Timeout:   20 * time.Second,
			Jar:       jar,
		}
	}

	return &DynamicClient{timeToLive: TTL, desiredHttpState: DesiredHttp, httpState: StateUnknown, fallbackClient: fallbackClient, http3Client: http3Client}
}

// ResponseAndError holds the response from a web request
type ResponseAndError struct {
	resp  *http.Response
	err   error
	http3 bool
}

// close You need to call Close on DynamicConnection once you are done using it
func (dc *DynamicClient) Close() {
	dc.mux.Lock()
	if p, ok := dc.http3Client.Transport.(*http3.Transport); ok {
		p.Close()
	}
	dc.mux.Unlock()
}

// Reset simulates a TTL expire
func (dc *DynamicClient) Reset() {
	dc.mux.Lock()
	if dc.desiredHttpState == StateHttp3 {
		dc.httpState = StateUnknown
	} else {
		dc.httpState = StateHttp
	}
	dc.mux.Unlock()
}

func (dc *DynamicClient) GetHttpClient() *http.Client {
	return dc.fallbackClient
}

// synchronouslyTestBoth when http3 needs to be revalidated,
// on first connect or TTL expire retest
// do call on both http and http3 clients, if http return first
// wait another 200 ms to make sure http3 isn't coming.
// if http3 doesn't come in time, cancel it and create go routine to wait until it's returned
// making sure we don't leak a file descriptor
func (dc *DynamicClient) synchronouslyTestBoth(req *http.Request) (*http.Response, HttpState, error) {
	ch := make(chan ResponseAndError)
	go func() {
		fmt.Println("trying http3 path")
		resp, err := dc.http3Client.Do(req)
		ret := ResponseAndError{resp: resp, err: err, http3: true}
		ch <- ret
	}()
	go func() {
		fmt.Println("trying http path")
		resp, err := dc.fallbackClient.Do(req)
		ret := ResponseAndError{resp: resp, err: err, http3: false}
		ch <- ret
	}()

	ret := <-ch

	if ret.http3 && ret.err == nil {
		go func() {
			fmt.Println("cleaning up http")
			httpRet := <-ch
			if httpRet.err == nil {
				fmt.Println("freeing slower http")
				httpRet.resp.Body.Close()
			}
		}()
		fmt.Println("return http3")
		return ret.resp, StateHttp3, ret.err
	}

	// http returned first, wait extra 200ms for http3
	var http3Ret ResponseAndError
	select {
	case http3Ret = <-ch:
		// Preferred endpoint responded in time
		if http3Ret.err == nil {
			// Close un-needed http resp
			if ret.resp != nil && ret.resp.Body != nil {
				ret.resp.Body.Close()
			}
			fmt.Println("return http3 before timeout")
			return http3Ret.resp, StateHttp3, http3Ret.err
		}
		fmt.Println("http3 err", http3Ret.err)
		return ret.resp, StateHttp, ret.err

	case <-time.After(200 * time.Millisecond):
	}

	fmt.Println("http3 endpoints timed out")
	go func() {
		fmt.Println("cleaning up http3 wait")
		http3Ret = <-ch
		if http3Ret.err != nil {
			fmt.Println("cleaning up http3 actual close")
			if http3Ret.resp != nil && http3Ret.resp.Body != nil {
				http3Ret.resp.Body.Close()
			}
		}
	}()

	// return http response
	fmt.Println("returning http3")
	return ret.resp, StateHttp, ret.err
}

// Do based on desired http protocol, try http3 and fallback to http if that fails
// only do both protocals when trying to figure out which you can use, can ove onto 'fast' path
// NewDynamicClient makes sure all pointers are inited
func (dc *DynamicClient) Do(req *http.Request) (resp *http.Response, err error) {
	if req == nil {
		return nil, fmt.Errorf("incoming http.Request pointer was nil")
	}

	dc.mux.RLock()
	desiredHttpState := dc.desiredHttpState
	connectionStart := dc.connectionStart
	timeToLive := dc.timeToLive
	dc.mux.RUnlock()

	// If we only want to use http
	if desiredHttpState == StateHttp {
		return dc.fallbackClient.Do(req)
	}

	// See if we need to retry Http3 connection
	if time.Since(connectionStart) > timeToLive {
		dc.mux.Lock()
		dc.connectionStart = time.Now()
		if dc.desiredHttpState == StateHttp {
			dc.httpState = StateHttp
		} else {
			dc.httpState = StateUnknown
		}
		dc.mux.Unlock()
	}

	dc.mux.RLock()
	originalEnabledHttp3 := dc.httpState
	dc.mux.RUnlock()

	var state HttpState
	if originalEnabledHttp3 == StateUnknown {
		resp, state, err = dc.synchronouslyTestBoth(req)
		dc.mux.Lock()
		dc.httpState = state
		dc.mux.Unlock()
		return
	}

	if originalEnabledHttp3 == StateHttp3 {
		resp, err = dc.http3Client.Do(req)
		if err != nil {
			fmt.Println("err =", err)
			dc.mux.Lock()
			dc.httpState = StateHttp
			dc.mux.Unlock()
			resp, err := dc.fallbackClient.Do(req)
			// try to reconnect using http3 next time,
			// if http3 fails and http works a second time, we'll switch to http
			if err == nil {
				dc.mux.Lock()
				dc.httpState = StateUnknown
				dc.mux.Unlock()
			}
			return resp, err
		}
		return resp, err
	}

	resp, err = dc.fallbackClient.Do(req)
	if err != nil {
		dc.mux.Lock()
		dc.httpState = originalEnabledHttp3
		dc.mux.Unlock()
	}
	return
}
