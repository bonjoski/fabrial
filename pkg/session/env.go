package session

import (
	"fmt"
	"sort"
	"strings"
)

// BuildEnvironment generates the ambient security environment map for an active session.
func BuildEnvironment(sessionID SessionID, parentID SessionID, token string, proxyAddr string, caCertPath string) map[string]string {
	env := map[string]string{
		"FABRIAL_SESSION_ACTIVE": "1",
		"FABRIAL_SESSION_ID":     string(sessionID),
		"AIRLOCK_ACTIVE":         "1",
	}

	if parentID != "" {
		env["FABRIAL_PARENT_SESSION_ID"] = string(parentID)
	}

	if token != "" {
		env["CONJOINER_TASK_TOKEN"] = token
	}

	if proxyAddr != "" {
		if !strings.HasPrefix(proxyAddr, "http://") && !strings.HasPrefix(proxyAddr, "https://") {
			proxyAddr = "http://" + proxyAddr
		}
		env["HTTP_PROXY"] = proxyAddr
		env["HTTPS_PROXY"] = proxyAddr
		env["http_proxy"] = proxyAddr
		env["https_proxy"] = proxyAddr
		env["SOVEREIGN_SHIELD_ACTIVE"] = "1"
	}

	if caCertPath != "" {
		env["SSL_CERT_FILE"] = caCertPath
		env["NODE_EXTRA_CA_CERTS"] = caCertPath
	}

	return env
}

// FormatShellExport converts an environment map into eval-safe POSIX shell export statements.
func FormatShellExport(env map[string]string) string {
	if len(env) == 0 {
		return ""
	}

	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		v := env[k]
		// Sanitize value for shell export: replace single quotes with '\''
		escapedVal := strings.ReplaceAll(v, "'", "'\\''")
		sb.WriteString(fmt.Sprintf("export %s='%s'\n", k, escapedVal))
	}

	return sb.String()
}
