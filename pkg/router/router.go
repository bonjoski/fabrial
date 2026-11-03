// Package router implements the multi-tier dynamic routing engine for Fabrial.
// It maps commands to Tier 1 (Airlock Kernel Sandbox) or Tier 2 (Aegisbox MicroVM).
package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/airlock/pkg/bridge"
	"github.com/bonjoski/fabrial/pkg/policy"
)

// ExecutionOptions holds the resolved runtime flags and parameters for execution.
type ExecutionOptions struct {
	Profile       string
	TierOverride  policy.Tier
	PolicyPath    string
	LeaseSecrets  string
	SessionTicket string
	SubagentTask  string
	Airgap        bool
	Net           bool
	NoAttestation bool
	Shield        bool
	Quiet         bool
	DryRun        bool
	Dir           string
	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
}

// Decision represents the dynamic routing choice made by the fabric router.
type Decision struct {
	Tier        policy.Tier
	Engine      string
	BinaryPath  string
	ExecArgs    []string
	InjectedEnv []string
	Reason      string
	Command     []string
	Options    *ExecutionOptions
	PolicyFile string
}

// ParseArgs parses command line arguments into ExecutionOptions and command arguments.
func ParseArgs(args []string) (*ExecutionOptions, []string, error) {
	opts := &ExecutionOptions{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}

	// Look for explicit separator "--"
	cmdIdx := -1
	for i, arg := range args {
		if arg == "--" {
			cmdIdx = i
			break
		}
	}

	var flagArgs []string
	var cmdArgs []string

	if cmdIdx != -1 {
		flagArgs = args[:cmdIdx]
		cmdArgs = args[cmdIdx+1:]
	} else {
		// No "--" separator; parse flags until first non-flag argument
		i := 0
		for i < len(args) {
			arg := args[i]
			if !strings.HasPrefix(arg, "-") {
				// First non-flag argument starts the command
				cmdArgs = args[i:]
				break
			}

			// Value-bearing flags that may be passed as "--flag value"
			if arg == "--profile" || arg == "-profile" ||
				arg == "--tier" || arg == "-tier" ||
				arg == "--policy" || arg == "-policy" || arg == "-c" ||
				arg == "--lease-secret" || arg == "-lease-secret" ||
				arg == "--session-ticket" || arg == "-session-ticket" ||
				arg == "--subagent-task" || arg == "-subagent-task" {
				flagArgs = append(flagArgs, arg)
				if i+1 < len(args) {
					flagArgs = append(flagArgs, args[i+1])
					i += 2
					continue
				}
			}

			flagArgs = append(flagArgs, arg)
			i++
		}
	}

	// Parse extracted flagArgs
	for i := 0; i < len(flagArgs); i++ {
		arg := flagArgs[i]

		switch {
		case arg == "--microvm" || arg == "-microvm":
			opts.TierOverride = policy.Tier2

		case arg == "--tier" || arg == "-tier":
			if i+1 >= len(flagArgs) {
				return nil, nil, fmt.Errorf("missing argument for %s", arg)
			}
			i++
			t, err := policy.ParseTier(flagArgs[i])
			if err != nil {
				return nil, nil, err
			}
			opts.TierOverride = t

		case strings.HasPrefix(arg, "--tier="):
			val := strings.TrimPrefix(arg, "--tier=")
			t, err := policy.ParseTier(val)
			if err != nil {
				return nil, nil, err
			}
			opts.TierOverride = t

		case arg == "--profile" || arg == "-profile":
			if i+1 >= len(flagArgs) {
				return nil, nil, fmt.Errorf("missing argument for %s", arg)
			}
			i++
			opts.Profile = flagArgs[i]

		case strings.HasPrefix(arg, "--profile="):
			opts.Profile = strings.TrimPrefix(arg, "--profile=")

		case arg == "--policy" || arg == "-policy" || arg == "-c":
			if i+1 >= len(flagArgs) {
				return nil, nil, fmt.Errorf("missing argument for %s", arg)
			}
			i++
			opts.PolicyPath = flagArgs[i]

		case strings.HasPrefix(arg, "--policy="):
			opts.PolicyPath = strings.TrimPrefix(arg, "--policy=")

		case arg == "--lease-secret" || arg == "-lease-secret":
			if i+1 >= len(flagArgs) {
				return nil, nil, fmt.Errorf("missing argument for %s", arg)
			}
			i++
			opts.LeaseSecrets = flagArgs[i]

		case strings.HasPrefix(arg, "--lease-secret="):
			opts.LeaseSecrets = strings.TrimPrefix(arg, "--lease-secret=")

		case arg == "--session-ticket" || arg == "-session-ticket":
			if i+1 >= len(flagArgs) {
				return nil, nil, fmt.Errorf("missing argument for %s", arg)
			}
			i++
			opts.SessionTicket = flagArgs[i]

		case strings.HasPrefix(arg, "--session-ticket="):
			opts.SessionTicket = strings.TrimPrefix(arg, "--session-ticket=")

		case arg == "--subagent-task" || arg == "-subagent-task":
			if i+1 >= len(flagArgs) {
				return nil, nil, fmt.Errorf("missing argument for %s", arg)
			}
			i++
			opts.SubagentTask = flagArgs[i]

		case strings.HasPrefix(arg, "--subagent-task="):
			opts.SubagentTask = strings.TrimPrefix(arg, "--subagent-task=")

		case arg == "--airgap" || arg == "-airgap":
			opts.Airgap = true

		case arg == "--net" || arg == "-net":
			opts.Net = true

		case arg == "--no-attestation" || arg == "-no-attestation":
			opts.NoAttestation = true

		case arg == "--shield" || arg == "-shield":
			opts.Shield = true

		case arg == "--quiet" || arg == "-quiet" || arg == "-q":
			opts.Quiet = true

		case arg == "--dry-run" || arg == "-dry-run":
			opts.DryRun = true
		}
	}

	if opts.Airgap && opts.Net {
		return nil, nil, errors.New("conflicting execution flags: --airgap and --net are mutually exclusive")
	}

	if opts.LeaseSecrets != "" {
		if err := validateLeaseSecrets(opts.LeaseSecrets); err != nil {
			return nil, nil, err
		}
	}

	return opts, cmdArgs, nil
}

var dangerousEnvVars = map[string]bool{
	"LD_PRELOAD":            true,
	"LD_LIBRARY_PATH":       true,
	"DYLD_INSERT_LIBRARIES": true,
	"DYLD_LIBRARY_PATH":     true,
	"DYLD_FRAMEWORK_PATH":   true,
	"PATH":                  true,
	"SHELL":                 true,
	"IFS":                   true,
	"BASH_ENV":              true,
	"ENV":                   true,
	"PYTHONPATH":            true,
	"NODE_OPTIONS":          true,
	"PERL5LIB":              true,
	"RUBYOPT":               true,
}

func validateLeaseSecrets(secrets string) error {
	keys := strings.Split(secrets, ",")
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if dangerousEnvVars[strings.ToUpper(k)] {
			return fmt.Errorf("insecure leased secret %q: reserved system environment variables cannot be leased", k)
		}
		for _, r := range k {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
				return fmt.Errorf("invalid leased secret identifier %q: must contain only alphanumeric characters and underscores", k)
			}
		}
	}
	return nil
}

// Route analyzes execution options, commands, and repository policy to produce a routing Decision.
func Route(opts *ExecutionOptions, cmdArgs []string) (*Decision, error) {
	if len(cmdArgs) == 0 || strings.TrimSpace(cmdArgs[0]) == "" {
		return nil, errors.New("no command specified for execution")
	}

	// 1. Explicit airgap safety check:
	// If explicit Tier 2 was requested alongside --airgap, fail closed immediately
	// because Tier 2 (microVM) does not support verified network airgap.
	if opts.TierOverride == policy.Tier2 && opts.Airgap {
		return nil, errors.New("Tier 2 (Aegisbox MicroVM) does not support verified network airgap; execution halted to prevent isolation inversion (use Tier 1 for kernel-enforced airgap)")
	}

	var selectedTier policy.Tier
	var matchReason string
	var policyFile string

	// 2. Discover and evaluate repository-level fabrial.yaml policy
	pol, fPath, err := policy.LoadPolicy(opts.PolicyPath, opts.Dir)
	if err != nil {
		return nil, fmt.Errorf("failed to load fabrial policy: %w", err)
	}
	policyFile = fPath

	// CLI override takes highest precedence
	if opts.TierOverride != policy.TierUnknown {
		selectedTier = opts.TierOverride
		matchReason = fmt.Sprintf("explicit CLI tier override (%s)", selectedTier.String())
	} else {
		selectedTier, matchReason = pol.Match(cmdArgs)

		// Airgap confinement guarantee:
		// If --airgap was requested and policy matched Tier 2, route to Tier 1 where Airlock's
		// kernel sandbox enforces 100% offline network airgap, preventing isolation inversion.
		if opts.Airgap && selectedTier == policy.Tier2 {
			selectedTier = policy.Tier1
			matchReason = "airgap requested: routed to Tier 1 kernel sandbox to guarantee offline isolation (preventing Tier 2 network egress)"
		}
	}

	// 3. Resolve target engine binary and build invocation arguments
	var targetEngine string
	var binPath string
	var execArgs []string

	// Build effective command args, wrapping build commands with soulcaster if enabled by policy
	effectiveCmdArgs := cmdArgs
	if !opts.NoAttestation && (pol.ShouldAttest(cmdArgs) || isBuildCommand(cmdArgs)) {
		if soulcasterBin, err := FindExecutable("soulcaster"); err == nil && soulcasterBin != "" {
			if len(cmdArgs) > 0 && cmdArgs[0] != "soulcaster" {
				effectiveCmdArgs = append([]string{"soulcaster", "wrap", "--"}, cmdArgs...)
			}
		}
	}

	// Shield in-flight secret wire guard environment injection
	shieldCfg := pol.GetShieldConfig()
	var injectedEnv []string
	if opts.Net || opts.Shield || (shieldCfg.Enabled && shieldCfg.AutoInjectEnv && opts.Net) {
		if addr, ok := DetectShieldProxy(shieldCfg.ProxyAddr); ok {
			injectedEnv = append(injectedEnv,
				"HTTP_PROXY=http://"+addr,
				"HTTPS_PROXY=http://"+addr,
				"http_proxy=http://"+addr,
				"https_proxy=http://"+addr,
				"SOVEREIGN_SHIELD_ACTIVE=1",
			)
		} else if shieldCfg.FailClosed && (opts.Net || opts.Shield) {
			return nil, errors.New("Shield wire guard proxy offline and fail-closed is active; execution halted to prevent credential leakage")
		}
	}

	// Conjoiner DPoP subagent task binding
	if opts.SubagentTask != "" {
		if err := validateSubagentTaskID(opts.SubagentTask); err != nil {
			return nil, fmt.Errorf("invalid subagent task ID: %w (fail-closed to prevent environment injection)", err)
		}
		injectedEnv = append(injectedEnv, "CONJOINER_TASK_ID="+opts.SubagentTask)
	}

	switch selectedTier {
	case policy.Tier1:
		targetEngine = "airlock"
		bin, err := FindExecutable("airlock")
		if err != nil {
			bin = "airlock"
		}
		binPath = bin

		execArgs = append(execArgs, "run")
		if opts.Profile != "" {
			execArgs = append(execArgs, "-profile", opts.Profile)
		}
		if opts.Airgap {
			execArgs = append(execArgs, "-airgap")
		}
		if opts.Net {
			execArgs = append(execArgs, "-net")
		}
		if opts.LeaseSecrets != "" {
			execArgs = append(execArgs, "-lease-secret", opts.LeaseSecrets)
		}
		if opts.SessionTicket != "" {
			execArgs = append(execArgs, "-session-ticket", opts.SessionTicket)
		}

		execArgs = append(execArgs, "--")
		execArgs = append(execArgs, effectiveCmdArgs...)

	case policy.Tier2:
		targetEngine = "aegisbox"
		bin, err := bridge.DiscoverAegisbox()
		if err != nil {
			// Fallback to local search
			bin, err = FindExecutable("aegisbox")
		}
		if err != nil {
			bin = "aegisbox"
		}
		binPath = bin

		execArgs = append(execArgs, "exec", "-engine", "microvm")
		if opts.Airgap {
			execArgs = append(execArgs, "-airgap")
		}
		if opts.LeaseSecrets != "" {
			execArgs = append(execArgs, "-allow-env", opts.LeaseSecrets)
		}

		execArgs = append(execArgs, "--")
		execArgs = append(execArgs, effectiveCmdArgs...)

	default:
		return nil, fmt.Errorf("unsupported tier: %v", selectedTier)
	}

	return &Decision{
		Tier:        selectedTier,
		Engine:      targetEngine,
		BinaryPath:  binPath,
		ExecArgs:    execArgs,
		InjectedEnv: injectedEnv,
		Reason:      matchReason,
		Command:     cmdArgs,
		Options:     opts,
		PolicyFile:  policyFile,
	}, nil
}

// Execute runs the command according to the routing Decision.
func Execute(ctx context.Context, dec *Decision) (int, error) {
	if dec.Tier == policy.Tier2 {
		if err := VerifyTier2Health(); err != nil {
			return 1, fmt.Errorf("fabrial: %w", err)
		}
	}

	if dec.Options != nil && !dec.Options.Quiet {
		banner := "💎 Fabrial Multi-Tier Router"
		switch dec.Tier {
		case policy.Tier1:
			fmt.Fprintf(dec.Options.Stderr, "%s: Routing to %s (<15ms cold start)\n   Policy Rationale: %s\n",
				banner, dec.Tier.String(), dec.Reason)
		case policy.Tier2:
			fmt.Fprintf(dec.Options.Stderr, "%s: Routing to %s (~100ms hardware isolation)\n   Policy Rationale: %s\n",
				banner, dec.Tier.String(), dec.Reason)
		}
	}

	if dec.Options != nil && dec.Options.DryRun {
		if len(dec.InjectedEnv) > 0 {
			fmt.Fprintf(dec.Options.Stdout, "Injected-Env: %s\n", strings.Join(dec.InjectedEnv, " "))
		}
		fmt.Fprintf(dec.Options.Stdout, "Dry-run: %s %s\n", dec.BinaryPath, strings.Join(dec.ExecArgs, " "))
		return 0, nil
	}

	cmd := exec.CommandContext(ctx, dec.BinaryPath, dec.ExecArgs...)
	if len(dec.InjectedEnv) > 0 {
		cmd.Env = append(os.Environ(), dec.InjectedEnv...)
	}
	if dec.Options != nil {
		if dec.Options.Dir != "" {
			cmd.Dir = dec.Options.Dir
		}
		cmd.Stdin = dec.Options.Stdin
		cmd.Stdout = dec.Options.Stdout
		cmd.Stderr = dec.Options.Stderr
	}

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return 1, err
	}

	return 0, nil
}

// FindExecutable searches for a binary on PATH and standard installation prefixes.
func FindExecutable(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}

	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join("/opt/homebrew/bin", name),
		filepath.Join("/usr/local/bin", name),
		filepath.Join(home, ".local", "bin", name),
		filepath.Join(home, "bin", name),
		filepath.Join(home, "go", "bin", name),
	}

	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() && (fi.Mode()&0111 != 0) {
			return c, nil
		}
	}

	return "", fmt.Errorf("%s binary not found on PATH or standard install directories", name)
}

// ResolveAegisboxSocketPath returns the path to the Aegisbox daemon Unix domain socket.
func ResolveAegisboxSocketPath() string {
	if s := os.Getenv("AEGISBOX_SOCKET"); s != "" {
		return s
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".aegisbox", "aegisboxd.sock")
	}
	return filepath.Join(os.TempDir(), "aegisboxd.sock")
}

// CheckAegisboxDaemon checks whether the Aegisbox resident daemon socket is online and connectable.
// Invariant #2: Fail-closed if socket permissions are insecure (non-0600), symlinked, or owned by another user.
func CheckAegisboxDaemon() (bool, string) {
	sockPath := ResolveAegisboxSocketPath()

	fi, err := os.Lstat(sockPath)
	if err != nil {
		return false, sockPath
	}

	if !verifySocketSecurity(fi) {
		return false, sockPath
	}

	conn, err := net.DialTimeout("unix", sockPath, 500*time.Millisecond)
	if err != nil {
		return false, sockPath
	}
	_ = conn.Close()
	return true, sockPath
}

// VerifyTier2Health checks that the Tier 2 microVM engine is available and active.
// Fails closed if the daemon socket is offline or the binary is not found to prevent isolation inversion.
func VerifyTier2Health() error {
	bin, err := bridge.DiscoverAegisbox()
	if err != nil {
		bin, err = FindExecutable("aegisbox")
	}
	if err != nil {
		return fmt.Errorf("Tier 2 hypervisor engine unavailable: aegisbox executable not found (%w)", err)
	}

	online, sockPath := CheckAegisboxDaemon()
	if !online {
		return fmt.Errorf("Tier 2 microVM isolation unavailable: daemon socket %s is offline (fail-closed to prevent isolation inversion; run 'fabrial daemon start' or use Tier 1)", sockPath)
	}

	_ = bin
	return nil
}

// validateSubagentTaskID asserts that task tokens contain only safe alphanumeric characters,
// hyphens, and underscores to prevent newline/environment injection into the execution plane.
func validateSubagentTaskID(taskID string) error {
	if taskID == "" {
		return nil
	}
	if len(taskID) > 128 {
		return errors.New("subagent task ID exceeds 128 character limit")
	}
	for _, r := range taskID {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return fmt.Errorf("invalid character %q in subagent task ID: must only contain [a-zA-Z0-9_-]", r)
		}
	}
	return nil
}

// isBuildCommand checks if the command arguments match a compiler or build pipeline tool.
// Unpeels wrappers like 'env' or '/usr/bin/env' and skips flags to defeat evasion.
func isBuildCommand(cmdArgs []string) bool {
	if len(cmdArgs) == 0 {
		return false
	}

	// Unwrap wrappers like "env" or "/usr/bin/env"
	args := cmdArgs
	for len(args) > 0 {
		base := strings.ToLower(filepath.Base(args[0]))
		base = strings.TrimSuffix(base, ".exe")
		if base == "env" {
			args = args[1:]
			// Skip env flags and KEY=VAL definitions
			for len(args) > 0 {
				if strings.HasPrefix(args[0], "-") {
					args = args[1:]
				} else if strings.Contains(args[0], "=") {
					args = args[1:]
				} else {
					break
				}
			}
			continue
		}
		break
	}

	if len(args) == 0 {
		return false
	}

	tool := strings.ToLower(filepath.Base(args[0]))
	tool = strings.TrimSuffix(tool, ".exe")

	switch tool {
	case "make", "cmake", "ninja", "gcc", "g++", "clang", "clang++", "rustc":
		return true

	case "go":
		// Find first non-flag subcommand
		for i := 1; i < len(args); i++ {
			arg := args[i]
			if strings.HasPrefix(arg, "-") {
				continue
			}
			if arg == "build" || arg == "install" {
				return true
			}
			if arg == "test" {
				// Check for -c flag which compiles a test binary
				for j := i + 1; j < len(args); j++ {
					if args[j] == "-c" || strings.HasPrefix(args[j], "-c=") {
						return true
					}
				}
			}
			break
		}
		return false

	case "cargo":
		// Find first non-flag subcommand
		for i := 1; i < len(args); i++ {
			arg := args[i]
			if strings.HasPrefix(arg, "-") {
				continue
			}
			if arg == "build" || arg == "check" {
				return true
			}
			break
		}
		return false

	default:
		return false
	}
}

// DetectShieldProxy checks if Shield local proxy is listening on preferred addrs, 127.0.0.1:8443, 127.0.0.1:8080, or SHIELD_PROXY_ADDR.
func DetectShieldProxy(preferred ...string) (string, bool) {
	if s := os.Getenv("SHIELD_PROXY_ADDR"); s != "" {
		if conn, err := net.DialTimeout("tcp", s, 150*time.Millisecond); err == nil {
			_ = conn.Close()
			return s, true
		}
	}
	var candidates []string
	for _, p := range preferred {
		if p != "" {
			candidates = append(candidates, p)
		}
	}
	candidates = append(candidates, "127.0.0.1:8443", "127.0.0.1:8080")
	for _, addr := range candidates {
		conn, err := net.DialTimeout("tcp", addr, 150*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return addr, true
		}
	}
	return "", false
}
