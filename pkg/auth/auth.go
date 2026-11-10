package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bonjoski/stoneward/pkg/client"
	"github.com/bonjoski/stoneward/pkg/policy"
)

var (
	ErrCredentialsRequired = errors.New("either email and password or an API token is required for authentication")
)

// LoginOptions encapsulates flags passed to fabrial auth login or fabrial register.
type LoginOptions struct {
	ServerURL    string
	Email        string
	Password     string
	Token        string
	TenantID     string
	ClientName   string
	UseLocksmith bool
	Insecure     bool
}

// NewTLSConfig returns the TLS client configuration for Stoneward control plane connections.
// When insecure is false (the default), strict X.509 verification and TLS 1.3 minimum are enforced.
func NewTLSConfig(insecure bool) *tls.Config {
	if insecure {
		return &tls.Config{
			InsecureSkipVerify: true,
		}
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: false,
	}
}

// Login authenticates Fabrial against the Stoneward cloud control plane,
// pulls down the latest signed policy bundle, and persists credentials.
func Login(ctx context.Context, opts LoginOptions) (*client.FabrialAuthContext, *policy.PolicyBundle, *policy.ToolchainPolicies, error) {
	serverURL := strings.TrimRight(opts.ServerURL, "/")
	if serverURL == "" {
		serverURL = "https://localhost:9443"
	}

	var authCtx client.FabrialAuthContext
	authCtx.ServerURL = serverURL

	tr := &http.Transport{
		TLSClientConfig: NewTLSConfig(opts.Insecure),
	}
	httpClient := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	var rawToken string
	if opts.Token != "" {
		// Use directly provided API token
		rawToken = opts.Token
		authCtx.Token = opts.Token
		authCtx.TenantID = opts.TenantID
		if authCtx.TenantID == "" {
			authCtx.TenantID = "bonjo-prod"
		}
		authCtx.CreatedAt = time.Now().UTC()
		authCtx.ExpiresAt = time.Now().UTC().Add(30 * 24 * time.Hour) // 30 day token lease
	} else if opts.Email != "" && opts.Password != "" {
		// Authenticate via email & password against /v1/auth/login requesting an agent client token
		clientName := opts.ClientName
		if clientName == "" {
			clientName = "Fabrial Workstation"
		}

		loginPayload, _ := json.Marshal(map[string]interface{}{
			"email":       opts.Email,
			"password":    opts.Password,
			"client_type": "agent",
			"client_name": clientName,
		})

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/v1/auth/login", bytes.NewReader(loginPayload))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to create login request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("connection to control plane failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			var errResp map[string]string
			_ = json.NewDecoder(resp.Body).Decode(&errResp)
			msg := errResp["message"]
			if msg == "" {
				msg = errResp["error"]
			}
			if msg == "" {
				msg = fmt.Sprintf("status code %d", resp.StatusCode)
			}
			return nil, nil, nil, fmt.Errorf("authentication failed: %s", msg)
		}

		var loginResult struct {
			Status string `json:"status"`
			Token  string `json:"token"`
			User   struct {
				UserID   string   `json:"user_id"`
				TenantID string   `json:"tenant_id"`
				OrgName  string   `json:"org_name"`
				Email    string   `json:"email"`
				Name     string   `json:"name"`
				Role     string   `json:"role"`
				Scopes   []string `json:"scopes"`
			} `json:"user"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&loginResult); err != nil {
			return nil, nil, nil, fmt.Errorf("invalid login response: %w", err)
		}

		rawToken = loginResult.Token
		authCtx.TenantID = loginResult.User.TenantID
		authCtx.UserID = loginResult.User.UserID
		authCtx.OrgName = loginResult.User.OrgName
		authCtx.Email = loginResult.User.Email
		authCtx.Name = loginResult.User.Name
		authCtx.Role = loginResult.User.Role
		authCtx.Scopes = loginResult.User.Scopes
		authCtx.CreatedAt = time.Now().UTC()
		authCtx.ExpiresAt = time.Now().UTC().Add(30 * 24 * time.Hour)
	} else {
		return nil, nil, nil, ErrCredentialsRequired
	}

	// 2. Locksmith Hardware Enclave Storage with Biometric Amortization
	if opts.UseLocksmith {
		lockKey := "stoneward_agent_token"
		if err := client.StoreLocksmithSecret(lockKey, rawToken); err == nil {
			authCtx.TokenStorage = "locksmith"
			authCtx.LocksmithKey = lockKey
			authCtx.Token = "" // Zero plaintext token before serializing to disk
		} else {
			authCtx.Token = rawToken
			authCtx.TokenStorage = "file"
		}
	} else {
		authCtx.Token = rawToken
		authCtx.TokenStorage = "file"
	}
	client.SetCachedToken(rawToken, 5*time.Minute)

	// 3. Pull down and cryptographically verify the policy bundle
	bundle, toolchain, err := client.PullAndVerifyPolicy(serverURL, rawToken, authCtx.TenantID, opts.Insecure)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to synchronize policy bundle: %w", err)
	}

	// 4. Persist authenticated session
	if err := client.SaveFabrialAuth(&authCtx); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to persist auth credentials: %w", err)
	}

	return &authCtx, bundle, toolchain, nil
}

// Register dynamically registers a new Fabrial agent client, issues an agent token,
// seals it in Locksmith, and synchronizes the latest signed policy bundle.
func Register(ctx context.Context, opts LoginOptions) (*client.FabrialAuthContext, *policy.PolicyBundle, *policy.ToolchainPolicies, error) {
	serverURL := strings.TrimRight(opts.ServerURL, "/")
	if serverURL == "" {
		serverURL = "https://localhost:9443"
	}

	if opts.Email == "" || opts.Password == "" {
		return nil, nil, nil, ErrCredentialsRequired
	}

	clientName := opts.ClientName
	if clientName == "" {
		clientName = "Fabrial Workstation"
	}

	var authCtx client.FabrialAuthContext
	authCtx.ServerURL = serverURL

	tr := &http.Transport{
		TLSClientConfig: NewTLSConfig(opts.Insecure),
	}
	httpClient := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	regPayload, _ := json.Marshal(map[string]interface{}{
		"email":       opts.Email,
		"password":    opts.Password,
		"client_name": clientName,
		"client_type": "agent",
		"scopes":      []string{"telemetry:write", "policy:read"},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/v1/auth/register-client", bytes.NewReader(regPayload))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to build registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connection to control plane failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		msg := errResp["message"]
		if msg == "" {
			msg = errResp["error"]
		}
		if msg == "" {
			msg = fmt.Sprintf("status code %d", resp.StatusCode)
		}
		return nil, nil, nil, fmt.Errorf("registration failed: %s", msg)
	}

	var regResult struct {
		Status   string   `json:"status"`
		Token    string   `json:"token"`
		ClientID string   `json:"client_id"`
		TenantID string   `json:"tenant_id"`
		OrgName  string   `json:"org_name"`
		Role     string   `json:"role"`
		Scopes   []string `json:"scopes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&regResult); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid registration response: %w", err)
	}

	rawToken := regResult.Token
	authCtx.TenantID = regResult.TenantID
	authCtx.UserID = regResult.ClientID
	authCtx.OrgName = regResult.OrgName
	authCtx.Email = opts.Email
	authCtx.Name = clientName
	authCtx.Role = regResult.Role
	authCtx.Scopes = regResult.Scopes
	authCtx.CreatedAt = time.Now().UTC()
	authCtx.ExpiresAt = time.Now().UTC().Add(30 * 24 * time.Hour)

	// Locksmith Hardware Enclave Storage with Biometric Amortization
	if opts.UseLocksmith {
		lockKey := "stoneward_agent_token"
		if err := client.StoreLocksmithSecret(lockKey, rawToken); err == nil {
			authCtx.TokenStorage = "locksmith"
			authCtx.LocksmithKey = lockKey
			authCtx.Token = "" // Zero plaintext token before serializing
		} else {
			authCtx.Token = rawToken
			authCtx.TokenStorage = "file"
		}
	} else {
		authCtx.Token = rawToken
		authCtx.TokenStorage = "file"
	}
	client.SetCachedToken(rawToken, 5*time.Minute)

	bundle, toolchain, err := client.PullAndVerifyPolicy(serverURL, rawToken, authCtx.TenantID, opts.Insecure)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to synchronize policy bundle: %w", err)
	}

	if err := client.SaveFabrialAuth(&authCtx); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to persist auth credentials: %w", err)
	}

	return &authCtx, bundle, toolchain, nil
}

// Status returns current authentication context and cached policy status.
func Status() (*client.FabrialAuthContext, *policy.PolicyBundle, error) {
	authCtx, err := client.LoadFabrialAuth()
	if err != nil {
		return nil, nil, err
	}

	bundle, _, _ := client.LoadCachedPolicy()
	return authCtx, bundle, nil
}

// Logout revokes and clears local authentication state.
func Logout() error {
	return client.ClearFabrialAuth()
}

// PullPolicy synchronizes the latest signed policy bundle using the active authentication token.
func PullPolicy(insecure bool) (*policy.PolicyBundle, *policy.ToolchainPolicies, error) {
	authCtx, err := client.LoadFabrialAuth()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot pull policy: %w", err)
	}

	tok, err := authCtx.ResolveToken()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot resolve token: %w", err)
	}

	return client.PullAndVerifyPolicy(authCtx.ServerURL, tok, authCtx.TenantID, insecure)
}
