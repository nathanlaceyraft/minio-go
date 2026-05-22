package protocolswitchingclient

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

const (
	// StateHttp client will use http1
	StateHttp1 = iota // 0
	// StateHttp3 client will use http3
	StateHttp3 // 1
)

// HttpState one of the 'enum' values above
type HttpState int

// DynamicClient holds the state and client for a http/http3 client connection
type DynamicClient struct {
	mux              sync.RWMutex
	desiredHttpState HttpState
	httpState        HttpState
	timeToLive       time.Duration
	connectionStart  time.Time
	http3Client      *http.Client //client connection used for http3 requests
	fallbackClient   *http.Client //client connection used for http reequest
}

// NewDynamicClient create a new DynamicClient
func NewDynamicClient(transport http.RoundTripper, jar *cookiejar.Jar, CheckRedirect func(_ *http.Request, _ []*http.Request) error, DesiredHttp HttpState, TTL time.Duration) *DynamicClient {
	/*	insecureSkipVerify := false
		//If the RoundTripper is actually a http.Transport pointer, use it's value for InsecureSkipVerify
		if p, ok := transport.(*http.Transport); ok && p.TLSClientConfig != nil {
			insecureSkipVerify = p.TLSClientConfig.InsecureSkipVerify
		}
	*/
	insecureSkipVerify := true

	http3Transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify, // For local dev/self-signed certs
			MinVersion:         tls.VersionTLS13,   // Lowest version that will support http3/quic
		},
	}

	// Create HTTP client using the HTTP/3 transport
	http3Client := &http.Client{
		Transport:     http3Transport,
		CheckRedirect: CheckRedirect,
	}

	fallbackClient := &http.Client{
		Transport:     transport,
		CheckRedirect: CheckRedirect,
	}

	//If jar is nil, this would core dump,
	//there is a difference between a unspecified jar, and Jar explictly set to nil
	if jar != nil {
		http3Client.Jar = jar
		fallbackClient.Jar = jar
	}

	return &DynamicClient{timeToLive: TTL, connectionStart: time.Now(), desiredHttpState: DesiredHttp, httpState: DesiredHttp, fallbackClient: fallbackClient, http3Client: http3Client}
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
	dc.httpState = dc.desiredHttpState
	dc.mux.Unlock()
}

func (dc *DynamicClient) GetHttpClient() *http.Client {
	return dc.fallbackClient
}

var http1once sync.Once

func http1oncelog() {
	fmt.Println("Only HTTP1 requested")
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
	currentHttpState := dc.httpState
	dc.mux.RUnlock()

	// If we only want to use http
	if desiredHttpState == StateHttp1 {
		http1once.Do(http1oncelog)
		return dc.fallbackClient.Do(req)
	}

	// See if we need to retry Http3 connection
	if time.Since(connectionStart) > timeToLive {
		dc.mux.Lock()
		dc.connectionStart = time.Now()
		dc.httpState = dc.desiredHttpState
		currentHttpState = dc.httpState
		dc.mux.Unlock()
	}

	if currentHttpState == StateHttp3 {
		resp, err = dc.http3Client.Do(req)
		if err != nil {
			dc.mux.Lock()
			dc.httpState = StateHttp1
			dc.mux.Unlock()
			log.Println("HTTP3 failed, switchingto HTTP1")
			return resp, err
		}
		log.Println("HTTP3 succeeded")
		return resp, err
	}

	log.Println("Fast HTTP1 path")
	//server is currently only excepting http requests, don't waste time on http3
	resp, err = dc.fallbackClient.Do(req)
	return
}
