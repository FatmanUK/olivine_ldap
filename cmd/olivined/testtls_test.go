package main

import (
	"crypto/tls"
	"testing"
)

// loadPair builds the TLS config run() would build.
func loadPair(t *testing.T, cfg config) *tls.Config {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(cfg.cert, cfg.key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
	}
}
