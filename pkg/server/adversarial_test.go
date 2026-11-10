package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestAdversarial_OriginSpoofing_SubdomainEvasion tests that malicious domains mimicking
// localhost or 127.0.0.1 (e.g. via subdomains or hyphenation) are strictly rejected.
func TestAdversarial_OriginSpoofing_SubdomainEvasion(t *testing.T) {
	srv := NewServer(Config{})

	maliciousOrigins := []string{
		"http://localhost.evil.com",
		"https://localhost.attacker.org",
		"http://localhost-attacker.com",
		"http://127.0.0.1.attacker.com",
		"http://127.0.0.1.nip.io",
		"http://evil.com/localhost",
		"null",
		"https://google.com",
	}

	for _, origin := range maliciousOrigins {
		t.Run(origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			req.Host = "127.0.0.1:9191"
			req.Header.Set("Origin", origin)
			w := httptest.NewRecorder()

			srv.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("FAIL-OPEN: server accepted malicious Origin %q with status %d (expected 403 Forbidden)", origin, w.Code)
			}
		})
	}

	validOrigins := []string{
		"http://localhost:1420",
		"http://localhost:3000",
		"http://127.0.0.1:9191",
		"http://127.0.0.1:5173",
		"tauri://localhost",
		"wails://wails.localhost",
	}

	for _, origin := range validOrigins {
		t.Run(origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			req.Host = "127.0.0.1:9191"
			req.Header.Set("Origin", origin)
			w := httptest.NewRecorder()

			srv.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("expected valid Origin %q to return 200, got: %d", origin, w.Code)
			}
		})
	}
}

// TestAdversarial_DNSRebinding_HostHeaderEvasion tests that Host header variations trying to
// rebind DNS to localhost are blocked.
func TestAdversarial_DNSRebinding_HostHeaderEvasion(t *testing.T) {
	srv := NewServer(Config{})

	maliciousHosts := []string{
		"localhost.evil.com:9191",
		"localhost.attacker.org",
		"127.0.0.1.nip.io:9191",
		"127.0.0.1.xip.io",
		"attacker.com",
		"attacker.com:9191",
	}

	for _, host := range maliciousHosts {
		t.Run(host, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			req.Host = host
			w := httptest.NewRecorder()

			srv.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("FAIL-OPEN: server accepted malicious Host header %q with status %d (expected 403 Forbidden)", host, w.Code)
			}
		})
	}

	validHosts := []string{
		"127.0.0.1:9191",
		"127.0.0.1",
		"localhost:9191",
		"localhost",
		"[::1]:9191",
	}

	for _, host := range validHosts {
		t.Run(host, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			req.Host = host
			w := httptest.NewRecorder()

			srv.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("expected valid Host header %q to return 200, got: %d", host, w.Code)
			}
		})
	}
}

// TestAdversarial_DaemonAction_PathInjection asserts that daemon endpoints enforce strict
// URL segment whitelisting and reject traversal or illegal action injections.
func TestAdversarial_DaemonAction_PathInjection(t *testing.T) {
	srv := NewServer(Config{})

	attackPaths := []struct {
		path         string
		expectedCode int
	}{
		{"/api/v1/daemons/../../etc/passwd/start", http.StatusBadRequest},
		{"/api/v1/daemons/argus/kill", http.StatusBadRequest},
		{"/api/v1/daemons/argus/rm_-rf", http.StatusBadRequest},
		{"/api/v1/daemons/argus/exec_arbitrary", http.StatusBadRequest},
		{"/api/v1/daemons/nonexistent_daemon/start", http.StatusNotFound},
	}

	for _, tc := range attackPaths {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			req.Host = "127.0.0.1:9191"
			req.Header.Set("Authorization", "Bearer "+srv.AuthToken())
			w := httptest.NewRecorder()

			srv.Handler().ServeHTTP(w, req)
			if w.Code != tc.expectedCode {
				t.Fatalf("expected path %q to return %d, got: %d (body: %s)", tc.path, tc.expectedCode, w.Code, w.Body.String())
			}
		})
	}
}

// TestAdversarial_SSE_ClientCapacityLimit asserts that the SSE subscriber pool enforces
// maxSSEClients (32) and returns 429 Too Many Requests when saturated.
func TestAdversarial_SSE_ClientCapacityLimit(t *testing.T) {
	srv := NewServer(Config{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Fill the SSE client capacity (32 clients)
	clients := make([]*http.Response, 0, maxSSEClients)
	for i := 0; i < maxSSEClients; i++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/events", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("failed to connect SSE client %d: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected client %d to connect with 200, got: %d", i, resp.StatusCode)
		}
		clients = append(clients, resp)
	}
	defer func() {
		for _, c := range clients {
			_ = c.Body.Close()
		}
	}()

	// The 33rd client must be rejected with 429 Too Many Requests
	req33, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/events", nil)
	resp33, err := http.DefaultClient.Do(req33)
	if err != nil {
		t.Fatalf("unexpected network failure on 33rd client: %v", err)
	}
	defer resp33.Body.Close()

	if resp33.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("FAIL-OPEN: expected 33rd SSE client to be rejected with 429 Too Many Requests, got: %d", resp33.StatusCode)
	}

	// Close one client and verify that a new client can now connect
	_ = clients[0].Body.Close()

	var respRetry *http.Response
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		reqRetry, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/events", nil)
		resp, rErr := http.DefaultClient.Do(reqRetry)
		if rErr == nil {
			if resp.StatusCode == http.StatusOK {
				respRetry = resp
				break
			}
			_ = resp.Body.Close()
		}
	}
	if respRetry == nil {
		t.Fatalf("expected retried client to succeed with 200 after capacity freed")
	}
	defer respRetry.Body.Close()
}

// TestAdversarial_FAB07_MutatingEndpointsRequireBearerToken verifies that mutating /api/v1/*
// endpoints require a valid 0600 server.token Bearer header and reject unauthenticated requests.
func TestAdversarial_FAB07_MutatingEndpointsRequireBearerToken(t *testing.T) {
	tokFile := t.TempDir() + "/server.token"
	srv := NewServer(Config{TokenPath: tokFile})

	endpoints := []string{
		"/api/v1/doctor/fix",
		"/api/v1/daemons/argus/stop",
		"/api/v1/daemons/locksmith/restart",
	}

	for _, ep := range endpoints {
		// 1. Missing Authorization header -> 401 Unauthorized
		reqNoAuth := httptest.NewRequest(http.MethodPost, ep, nil)
		reqNoAuth.Host = "127.0.0.1:9191"
		wNoAuth := httptest.NewRecorder()
		srv.Handler().ServeHTTP(wNoAuth, reqNoAuth)
		if wNoAuth.Code != http.StatusUnauthorized {
			t.Fatalf("FAIL-OPEN (FAB-07): unauthenticated POST %s returned %d, want 401", ep, wNoAuth.Code)
		}

		// 2. Wrong Bearer token -> 401 Unauthorized
		reqBad := httptest.NewRequest(http.MethodPost, ep, nil)
		reqBad.Host = "127.0.0.1:9191"
		reqBad.Header.Set("Authorization", "Bearer deadbeefbadtoken")
		wBad := httptest.NewRecorder()
		srv.Handler().ServeHTTP(wBad, reqBad)
		if wBad.Code != http.StatusUnauthorized {
			t.Fatalf("FAIL-OPEN (FAB-07): wrong-token POST %s returned %d, want 401", ep, wBad.Code)
		}
	}
}
