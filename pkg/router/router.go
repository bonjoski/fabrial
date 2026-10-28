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
	Airgap        bool
	Net           bool
	Quiet         bool
	DryRun        bool
	Dir           string
	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
}

// Decision represents the dynamic routing choice made by the fabric router.
type Decision struct {
	Tier       policy.Tier
	Engine     string
	BinaryPath string
	ExecArgs   []string
	Reason     string
	Command    []string
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
				arg == "--session-ticket" || arg == "-session-ticket" {
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

		case arg == "--airgap" || arg == "-airgap":
			opts.Airgap = true

		case arg == "--net" || arg == "-net":
			opts.Net = true

		case arg == "--quiet" || arg == "-quiet" || arg == "-q":
			opts.Quiet = true

		case arg == "--dry-run" || arg == "-dry-run":
			opts.DryRun = true
		}
	}

	return opts, cmdArgs, nil
}

// Route analyzes execution options, commands, and repository policy to produce a routing Decision.
func Route(opts *ExecutionOptions, cmdArgs []string) (*Decision, error) {
	if len(cmdArgs) == 0 {
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

	// 2. Explicit CLI override takes highest precedence
	if opts.TierOverride != policy.TierUnknown {
		selectedTier = opts.TierOverride
		matchReason = fmt.Sprintf("explicit CLI tier override (%s)", selectedTier.String())
	} else {
		// 3. Discover and evaluate repository-level fabrial.yaml policy
		pol, fPath, err := policy.LoadPolicy(opts.PolicyPath, opts.Dir)
		if err != nil {
			return nil, fmt.Errorf("failed to load fabrial policy: %w", err)
		}
		policyFile = fPath
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
		execArgs = append(execArgs, cmdArgs...)

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
		execArgs = append(execArgs, cmdArgs...)

	default:
		return nil, fmt.Errorf("unsupported tier: %v", selectedTier)
	}

	return &Decision{
		Tier:       selectedTier,
		Engine:     targetEngine,
		BinaryPath: binPath,
		ExecArgs:   execArgs,
		Reason:     matchReason,
		Command:    cmdArgs,
		Options:    opts,
		PolicyFile: policyFile,
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
		fmt.Fprintf(dec.Options.Stdout, "Dry-run: %s %s\n", dec.BinaryPath, strings.Join(dec.ExecArgs, " "))
		return 0, nil
	}

	cmd := exec.CommandContext(ctx, dec.BinaryPath, dec.ExecArgs...)
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
func CheckAegisboxDaemon() (bool, string) {
	sockPath := ResolveAegisboxSocketPath()
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
