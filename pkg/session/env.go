package session

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var validEnvKeyRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// BuildEnvironment generates the strictly local, PANW Safe Harbor compliant
// ambient security environment map for an active session.
// If FABRIAL_WORKTREE_ROOT is set in the process environment, it also exports
// FABRIAL_WORKTREE_ROOT and FABRIAL_RECEIPT_DIR.
func BuildEnvironment(sessionID SessionID, parentID SessionID, token string, proxyAddr string, caCertPath string) map[string]string {
	return BuildEnvironmentWithWorkspace(sessionID, parentID, token, proxyAddr, caCertPath, os.Getenv("FABRIAL_WORKTREE_ROOT"))
}

// BuildEnvironmentWithWorkspace generates the strictly local ambient security
// environment map for an active session bound to worktreeRoot.
// Per SEC-PANW-01, zero cloud control plane variables (STONEWARD_*, etc.) are exported.
func BuildEnvironmentWithWorkspace(sessionID SessionID, parentID SessionID, token string, proxyAddr string, caCertPath string, worktreeRoot string) map[string]string {
	env := map[string]string{
		"FABRIAL_SESSION_ACTIVE": "1",
		"FABRIAL_SESSION_ID":     string(sessionID),
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

	if root := strings.TrimSpace(worktreeRoot); root != "" {
		cleanRoot := filepath.Clean(root)
		env["FABRIAL_WORKTREE_ROOT"] = cleanRoot
		if sid := string(sessionID); isSafeReceiptPathSegment(sid) {
			env["FABRIAL_RECEIPT_DIR"] = filepath.Join(cleanRoot, ".fabrial", "receipts", sid)
		}
	}

	return env
}

func isSafeReceiptPathSegment(seg string) bool {
	if seg == "" || strings.Contains(seg, "..") || strings.ContainsAny(seg, `/\`) {
		return false
	}
	return true
}

// FormatShellExport converts an environment map into eval-safe POSIX shell export statements,
// strictly rejecting illegal environment variable names and stripping shell metacharacters/newlines.
func FormatShellExport(env map[string]string) string {
	if len(env) == 0 {
		return ""
	}

	keys := make([]string, 0, len(env))
	for k := range env {
		if validEnvKeyRegex.MatchString(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		v := env[k]
		// Strictly strip null bytes and line breaks to prevent subshell/command smuggling
		v = strings.ReplaceAll(v, "\x00", "")
		v = strings.ReplaceAll(v, "\r", "")
		v = strings.ReplaceAll(v, "\n", "")
		// Sanitize value for shell export: replace single quotes with '\''
		escapedVal := strings.ReplaceAll(v, "'", "'\\''")
		sb.WriteString(fmt.Sprintf("export %s='%s'\n", k, escapedVal))
	}

	return sb.String()
}
