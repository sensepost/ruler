package utils

import (
	"net/http"
	"sync"
)

type withHeader struct {
	mu sync.RWMutex
	http.Header
	rt http.RoundTripper
}

func WithHeader(rt http.RoundTripper) *withHeader {
	if rt == nil {
		rt = http.DefaultTransport
	}

	return &withHeader{Header: make(http.Header), rt: rt}
}

func (h *withHeader) RoundTrip(req *http.Request) (*http.Response, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if len(h.Header) == 0 {
		return h.rt.RoundTrip(req)
	}

	req = req.Clone(req.Context())
	for k, v := range h.Header {
		req.Header[k] = v
	}

	return h.rt.RoundTrip(req)
}

func (h *withHeader) Set(k, v string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.Header.Set(k, v)
}
