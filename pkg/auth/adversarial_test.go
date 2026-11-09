package auth

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAdversarial_FAB03_StrictTLSByDefault verifies that TLS verification is enabled by default,
// enforces TLS 1.3 minimum, and rejects untrusted/self-signed control plane certificates.
func TestAdversarial_FAB03_StrictTLSByDefault(t *testing.T) {
	cfg := NewTLSConfig(false)
	if cfg.InsecureSkipVerify {
		t.Fatal("FAIL-OPEN (FAB-03): NewTLSConfig(false) set InsecureSkipVerify=true")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("expected MinVersion TLS 1.3 (%x), got %x", tls.VersionTLS13, cfg.MinVersion)
	}

	insecureCfg := NewTLSConfig(true)
	if !insecureCfg.InsecureSkipVerify {
		t.Fatal("expected NewTLSConfig(true) to enable InsecureSkipVerify for explicit --insecure-tls")
	}

	// Spin up self-signed TLS server attempting to MITM /v1/auth/login
	mitmSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","token":"forged"}`))
	}))
	defer mitmSrv.Close()

	_, _, _, err := Login(context.Background(), LoginOptions{
		ServerURL: mitmSrv.URL,
		Email:     "op@example.com",
		Password:  "secret",
		Insecure:  false, // default secure posture
	})
	if err == nil {
		t.Fatal("FAIL-OPEN (FAB-03): Login accepted self-signed MITM TLS server when Insecure=false")
	}
}
