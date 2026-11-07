package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/bonjoski/fabrial/pkg/session"
	"github.com/bonjoski/stoneward/pkg/client"
	"github.com/bonjoski/stoneward/pkg/policy"
)

func TestAuth_LoginStatusLogout(t *testing.T) {
	tmpDir := t.TempDir()
	authFile := filepath.Join(tmpDir, "auth.json")
	policyFile := filepath.Join(tmpDir, "policy_cache.json")
	t.Setenv("FABRIAL_AUTH_FILE", authFile)
	t.Setenv("FABRIAL_POLICY_FILE", policyFile)
	t.Setenv("FABRIAL_AUTH_TOKEN", "")
	t.Setenv("STONEWARD_TOKEN", "")

	// 1. Setup mock Stoneward server
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	_ = pub

	bundle := &policy.PolicyBundle{
		TenantID:   "tenant-bonjo",
		Version:    1,
		CreatedAt:  time.Now().UTC(),
		ValidUntil: time.Now().UTC().Add(48 * time.Hour),
		Rule: policy.PolicyRule{
			AllowedTools:     []string{"read_file", "git_status"},
			BlockedSyscalls:  []string{"ptrace", "reboot"},
			BlockLoopbackNet: true,
		},
	}
	if err := bundle.Sign(priv); err != nil {
		t.Fatalf("failed to sign bundle: %v", err)
	}
	toolchain := policy.DefaultToolchainPolicies()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/login":
			var req map[string]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["email"] != "ben@bonjo.dev" || req["password"] != "correct-pass" {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "authenticated",
				"token":  "stnw_live_test_token_abc123",
				"user": map[string]interface{}{
					"user_id":   "user-101",
					"tenant_id": "tenant-bonjo",
					"org_name":  "Bonjo",
					"email":     "ben@bonjo.dev",
					"name":      "Ben Skolmoski",
					"role":      "admin",
				},
			})
		case "/v1/policy":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(bundle)
		case "/v1/policy/tools":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(toolchain)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// 2. Test initial status is unauthenticated
	_, _, err = Status()
	if err == nil {
		t.Fatal("expected Status to return error when unauthenticated")
	}

	// 3. Test Login
	authCtx, pulledBundle, pulledTools, err := Login(context.Background(), LoginOptions{
		ServerURL: srv.URL,
		Email:     "ben@bonjo.dev",
		Password:  "correct-pass",
		Insecure:  true,
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if authCtx.Token != "stnw_live_test_token_abc123" {
		t.Fatalf("unexpected token: %s", authCtx.Token)
	}
	if authCtx.TenantID != "tenant-bonjo" {
		t.Fatalf("unexpected tenant ID: %s", authCtx.TenantID)
	}
	if pulledBundle.TenantID != "tenant-bonjo" {
		t.Fatalf("unexpected bundle tenant: %s", pulledBundle.TenantID)
	}
	if len(pulledTools.Argus.AllowedRegistries) == 0 {
		t.Fatal("expected toolchain policies to be populated")
	}

	// 4. Test Status after login
	statusAuth, statusBundle, err := Status()
	if err != nil {
		t.Fatalf("Status failed after login: %v", err)
	}
	if statusAuth.Email != "ben@bonjo.dev" {
		t.Fatalf("unexpected status email: %s", statusAuth.Email)
	}
	if statusBundle.TenantID != "tenant-bonjo" {
		t.Fatalf("unexpected status bundle: %s", statusBundle.TenantID)
	}

	// 5. Test Ambient Session Injection
	env := session.BuildEnvironment("master-1", "", "token-1", "", "")
	if env["FABRIAL_AUTH_TOKEN"] != "stnw_live_test_token_abc123" {
		t.Fatalf("expected FABRIAL_AUTH_TOKEN in environment, got: %s", env["FABRIAL_AUTH_TOKEN"])
	}
	if env["STONEWARD_TENANT_ID"] != "tenant-bonjo" {
		t.Fatalf("expected STONEWARD_TENANT_ID in environment, got: %s", env["STONEWARD_TENANT_ID"])
	}

	// 6. Test Policy Pull
	rePulledBundle, _, err := PullPolicy(true)
	if err != nil {
		t.Fatalf("PullPolicy failed: %v", err)
	}
	if rePulledBundle.TenantID != "tenant-bonjo" {
		t.Fatalf("unexpected re-pulled bundle tenant: %s", rePulledBundle.TenantID)
	}

	// 7. Test Logout
	if err := Logout(); err != nil {
		t.Fatalf("Logout failed: %v", err)
	}
	if client.IsFabrialAuthenticated() {
		t.Fatal("expected IsFabrialAuthenticated to be false after logout")
	}
}
