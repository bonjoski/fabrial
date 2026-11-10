package server

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/fabrial/pkg/doctor"
	"github.com/bonjoski/fabrial/pkg/supervisor"
	"github.com/bonjoski/fabrial/pkg/version"
)

func TestServer_HealthEndpoint(t *testing.T) {
	srv := NewServer(Config{})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Host = "127.0.0.1"
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got: %d", w.Code)
	}

	var res map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}

	if res["status"] != "ok" {
		t.Errorf("expected status ok, got: %v", res["status"])
	}
	if res["version"] != version.Version {
		t.Errorf("expected version %s, got: %v", version.Version, res["version"])
	}
}

func TestServer_DoctorEndpoint(t *testing.T) {
	srv := NewServer(Config{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/doctor", nil)
	req.Host = "127.0.0.1"
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got: %d", w.Code)
	}

	var reports []doctor.PillarHealth
	if err := json.Unmarshal(w.Body.Bytes(), &reports); err != nil {
		t.Fatalf("failed to decode doctor json: %v", err)
	}

	if len(reports) != len(doctor.CanonicalOrder) {
		t.Fatalf("expected %d pillars in doctor response, got: %d", len(doctor.CanonicalOrder), len(reports))
	}
}

func TestServer_DaemonsEndpoint(t *testing.T) {
	srv := NewServer(Config{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/daemons", nil)
	req.Host = "127.0.0.1"
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got: %d", w.Code)
	}

	var statuses []supervisor.ServiceStatus
	if err := json.Unmarshal(w.Body.Bytes(), &statuses); err != nil {
		t.Fatalf("failed to decode daemons json: %v", err)
	}

	if len(statuses) < 5 {
		t.Fatalf("expected at least 5 daemons in response, got: %d", len(statuses))
	}
}

func TestServer_DNSRebindingAndCSRFProtection(t *testing.T) {
	srv := NewServer(Config{})

	// 1. Foreign Host Header
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Host = "evil-rebinding.com:9191"
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for foreign Host header, got: %d", w.Code)
	}

	// 2. Foreign Origin Header
	req2 := httptest.NewRequest(http.MethodGet, "/health", nil)
	req2.Host = "127.0.0.1:9191"
	req2.Header.Set("Origin", "https://malicious-website.com")
	w2 := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for foreign Origin header, got: %d", w2.Code)
	}

	// 3. Allowed Local Origin
	req3 := httptest.NewRequest(http.MethodGet, "/health", nil)
	req3.Host = "127.0.0.1:9191"
	req3.Header.Set("Origin", "tauri://localhost")
	w3 := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for tauri://localhost, got: %d", w3.Code)
	}
}

func TestServer_EventsSSE(t *testing.T) {
	srv := NewServer(Config{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/events", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to connect to SSE stream: %v", err)
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)

	// Read initial connected event
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read from SSE: %v", err)
	}
	if !strings.HasPrefix(line, "event: connected") {
		t.Fatalf("expected initial event: connected, got: %s", line)
	}

	// Trigger broadcast
	go func() {
		time.Sleep(50 * time.Millisecond)
		srv.BroadcastEvent(`{"status":"online"}`)
	}()

	// Wait for broadcast line
	found := false
	for i := 0; i < 5; i++ {
		l, rErr := reader.ReadString('\n')
		if rErr != nil {
			break
		}
		if strings.Contains(l, "online") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("did not receive broadcasted SSE event")
	}
}

func TestServer_SocketLifecycle(t *testing.T) {
	// macOS Unix domain socket length limitation: keep short in os.TempDir()
	sockPath := filepath.Join(os.TempDir(), "fab_srv_test.sock")
	_ = os.Remove(sockPath)

	srv := NewServer(Config{
		SocketPath: sockPath,
	})

	ctx := context.Background()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("failed to start server on socket: %v", err)
	}

	// Verify socket file created and has 0600 permissions
	fi, err := os.Lstat(sockPath)
	if err != nil {
		t.Fatalf("expected socket file to exist: %v", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("expected mode socket, got: %v", fi.Mode())
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0600 {
		t.Fatalf("expected socket permissions 0600, got: %04o", fi.Mode().Perm())
	}

	// Verify HTTP over Unix socket
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			},
		},
	}

	resp, err := client.Get("http://unix/health")
	if err != nil {
		t.Fatalf("failed to GET /health over unix socket: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got: %d", resp.StatusCode)
	}

	// Stop server and verify socket cleaned up
	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("failed to stop server: %v", err)
	}

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("expected socket file to be unlinked after shutdown")
	}
}
