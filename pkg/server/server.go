// Package server provides the local IPC and HTTP control plane API server for Fabrial,
// powering the Cockpit companion UI, IDE sidecars, and background telemetry.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/fabrial/pkg/doctor"
	"github.com/bonjoski/fabrial/pkg/supervisor"
	"github.com/bonjoski/fabrial/pkg/version"
)

// maxSSEClients defines the maximum concurrent SSE telemetry subscribers to prevent DoS.
const maxSSEClients = 32

// Config holds runtime configuration for the Fabrial API server.
type Config struct {
	SocketPath string
	TCPAddr    string
	Doctor     *doctor.Inspector
	Supervisor *supervisor.Supervisor
}

// DefaultSocketPath returns the standard location for ~/.fabrial/fabrial.sock.
func DefaultSocketPath() string {
	if s := os.Getenv("FABRIAL_SOCKET"); s != "" {
		return s
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".fabrial", "fabrial.sock")
	}
	return filepath.Join(os.TempDir(), "fabrial.sock")
}

// Server serves the Fabrial control plane over Unix socket and/or TCP.
type Server struct {
	cfg        Config
	mux        *http.ServeMux
	httpSrv    *http.Server
	listeners  []net.Listener
	mu         sync.Mutex
	sseClients map[chan string]struct{}
	sseMu      sync.RWMutex
}

// NewServer initializes a new Fabrial control plane server.
func NewServer(cfg Config) *Server {
	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultSocketPath()
	}
	if cfg.Doctor == nil {
		cfg.Doctor = doctor.NewInspector(500 * time.Millisecond)
	}
	if cfg.Supervisor == nil {
		cfg.Supervisor = supervisor.NewDefaultSupervisor()
	}

	s := &Server{
		cfg:        cfg,
		mux:        http.NewServeMux(),
		sseClients: make(map[chan string]struct{}),
	}

	s.setupRoutes()
	return s
}

// setupRoutes registers all control plane endpoints with DNS rebinding defenses.
func (s *Server) setupRoutes() {
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/api/v1/health", s.handleHealth)
	s.mux.HandleFunc("/api/v1/doctor", s.handleDoctor)
	s.mux.HandleFunc("/api/v1/daemons", s.handleDaemons)
	s.mux.HandleFunc("/api/v1/daemons/", s.handleDaemonAction)
	s.mux.HandleFunc("/api/v1/events", s.handleEvents)
}

// Handler returns the HTTP handler with host/origin validation to defeat DNS rebinding.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Invariant: Path traversal strictly rejected (fail-closed)
		if strings.Contains(r.URL.RawPath, "..") || strings.Contains(r.URL.Path, "..") {
			http.Error(w, "Bad Request: Path traversal forbidden", http.StatusBadRequest)
			return
		}

		// Invariant: For TCP requests, reject foreign origins to prevent CSRF / DNS rebinding
		if r.TLS == nil && r.Host != "" && !isLocalHost(r.Host) {
			http.Error(w, "Forbidden: Invalid Host header for local control plane", http.StatusForbidden)
			return
		}

		origin := r.Header.Get("Origin")
		if origin != "" && !isLocalOrigin(origin) {
			http.Error(w, "Forbidden: Cross-origin access disallowed", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		s.mux.ServeHTTP(w, r)
	})
}

func isLocalHost(host string) bool {
	h := host
	if strings.Contains(h, ":") {
		var err error
		h, _, err = net.SplitHostPort(host)
		if err != nil {
			h = strings.Trim(host, "[]")
		}
	}
	return h == "127.0.0.1" || h == "localhost" || h == "::1" || h == "unix" || h == ""
}

func isLocalOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Scheme == "tauri" || u.Scheme == "wails" {
		return true
	}
	if u.Scheme == "http" || u.Scheme == "https" {
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"version":   version.Version,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleDoctor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	targetPath := r.URL.Query().Get("path")
	if targetPath == "" {
		targetPath = "."
	}
	reports := s.cfg.Doctor.InspectAll(r.Context(), targetPath)
	_ = json.NewEncoder(w).Encode(reports)
}

func (s *Server) handleDaemons(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	statuses := s.cfg.Supervisor.StatusAll(r.Context())
	_ = json.NewEncoder(w).Encode(statuses)
}

func (s *Server) handleDaemonAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Path format: /api/v1/daemons/{name}/{action}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 5 {
		http.Error(w, "Invalid path: expected /api/v1/daemons/{name}/{start|stop|restart}", http.StatusBadRequest)
		return
	}

	name := parts[3]
	action := parts[4]

	// Invariant: Action whitelist enforcement
	allowedActions := map[string]bool{"start": true, "stop": true, "restart": true}
	if !allowedActions[action] {
		http.Error(w, fmt.Sprintf("Unsupported action %q (allowed: start, stop, restart)", action), http.StatusBadRequest)
		return
	}

	def, ok := s.cfg.Supervisor.GetService(name)
	if !ok {
		http.Error(w, fmt.Sprintf("Unknown daemon: %q", name), http.StatusNotFound)
		return
	}

	var status supervisor.ServiceStatus
	ctx := r.Context()

	switch action {
	case "start":
		status = s.cfg.Supervisor.StartService(ctx, def)
	case "stop":
		status = s.cfg.Supervisor.StopService(ctx, def)
	case "restart":
		s.cfg.Supervisor.StopService(ctx, def)
		time.Sleep(200 * time.Millisecond)
		status = s.cfg.Supervisor.StartService(ctx, def)
	}

	s.BroadcastEvent(fmt.Sprintf(`{"type":"daemon_state_change","service":%q,"state":%q}`, name, status.State))
	_ = json.NewEncoder(w).Encode(status)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	s.sseMu.Lock()
	if len(s.sseClients) >= maxSSEClients {
		s.sseMu.Unlock()
		http.Error(w, "Too Many Requests: SSE client pool capacity reached", http.StatusTooManyRequests)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	msgChan := make(chan string, 16)
	s.sseClients[msgChan] = struct{}{}
	s.sseMu.Unlock()

	defer func() {
		s.sseMu.Lock()
		delete(s.sseClients, msgChan)
		close(msgChan)
		s.sseMu.Unlock()
	}()

	// Send initial connection event
	_, _ = fmt.Fprintf(w, "event: connected\ndata: {\"version\":%q}\n\n", version.Version)
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-msgChan:
			_, _ = fmt.Fprintf(w, "event: update\ndata: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

// BroadcastEvent pushes a telemetry payload to all active SSE subscribers.
func (s *Server) BroadcastEvent(payload string) {
	s.sseMu.RLock()
	defer s.sseMu.RUnlock()

	for ch := range s.sseClients {
		select {
		case ch <- payload:
		default:
		}
	}
}

// Start begins serving on configured endpoints.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.httpSrv = &http.Server{
		Handler:      s.Handler(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	// 1. Setup Unix socket listener
	if s.cfg.SocketPath != "" {
		if err := os.MkdirAll(filepath.Dir(s.cfg.SocketPath), 0700); err != nil {
			return fmt.Errorf("failed to create socket directory: %w", err)
		}
		if rmErr := os.Remove(s.cfg.SocketPath); rmErr != nil && !os.IsNotExist(rmErr) {
			return fmt.Errorf("failed to unlink pre-existing socket %s: %w", s.cfg.SocketPath, rmErr)
		}

		ln, err := net.Listen("unix", s.cfg.SocketPath)
		if err != nil {
			return fmt.Errorf("failed to bind unix socket %s: %w", s.cfg.SocketPath, err)
		}
		if chmodErr := os.Chmod(s.cfg.SocketPath, 0600); chmodErr != nil {
			_ = ln.Close()
			return fmt.Errorf("failed to set 0600 permissions on unix socket %s: %w", s.cfg.SocketPath, chmodErr)
		}
		s.listeners = append(s.listeners, ln)
	}

	// 2. Setup TCP listener if requested
	if s.cfg.TCPAddr != "" {
		ln, err := net.Listen("tcp", s.cfg.TCPAddr)
		if err != nil {
			return fmt.Errorf("failed to bind TCP addr %s: %w", s.cfg.TCPAddr, err)
		}
		s.listeners = append(s.listeners, ln)
	}

	for _, ln := range s.listeners {
		go func(l net.Listener) {
			_ = s.httpSrv.Serve(l)
		}(ln)
	}

	return nil
}

// Stop gracefully shuts down the server and removes socket files.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	if s.httpSrv != nil {
		err = s.httpSrv.Shutdown(ctx)
	}

	if s.cfg.SocketPath != "" {
		if fi, statErr := os.Lstat(s.cfg.SocketPath); statErr == nil && fi.Mode()&os.ModeSymlink == 0 {
			if rmErr := os.Remove(s.cfg.SocketPath); rmErr != nil && !os.IsNotExist(rmErr) {
				// Cleaned or non-fatal
			}
		}
	}

	return err
}
