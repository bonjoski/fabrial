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
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bonjoski/airlock/pkg/bridge"
	"github.com/bonjoski/fabrial/pkg/pillars"
	"github.com/bonjoski/fabrial/pkg/policy"
	"github.com/bonjoski/fabrial/pkg/procident"
	"github.com/bonjoski/fabrial/pkg/queue"
)

var (
	tier2QueueMu sync.Mutex
	tier2Queues  = make(map[string]*queue.MicroVMQueue)
	tier2ReqSeq  atomic.Uint64
)

func getTier2ExecutionQueue() *queue.MicroVMQueue {
	lockDir := queue.DefaultQueueLockDir()
	key := lockDir + "|" + os.Getenv("FABRIAL_MAX_MICROVM_SLOTS")

	tier2QueueMu.Lock()
	defer tier2QueueMu.Unlock()

	if q, ok := tier2Queues[key]; ok {
		return q
	}
	q := queue.NewCrossProcessMicroVMQueue(
		lockDir,
		queue.WithMaxQueueCapacity(32),
		queue.WithPerSessionLimit(1),
		queue.WithDefaultWaitTimeout(60*time.Second),
	)
	tier2Queues[key] = q
	return q
}

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
	Stdin          io.Reader
	Stdout         io.Writer
	Stderr         io.Writer
	PillarResolver *pillars.Resolver
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
	Options     *ExecutionOptions
	PolicyFile  string
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

var (
	reSubshellChaining = regexp.MustCompile(`(?i)(\$\(.*\)|` + "`.*`" + `|;\s*(curl|wget|bash|sh|nc|python|perl|eval|exec)|\|\|\s*(curl|wget|bash|sh)|&&\s*(curl|wget|bash|sh|nc))`)
	reFuzzingAnomalies = regexp.MustCompile(`(?i)(%[0-9a-f]{2}){8,}|(\x00|\x1b)|(\.\./){4,}|/proc/self/(mem|environ)`)
	reInlineEvalNet    = regexp.MustCompile(`(?i)(-c|-e|\beval\b).*(\bsocket\b|\bnet\b|\bhttp\b|\burllib\b|requests|fetch|tls|miren)`)
	reZipSlipTraversal = regexp.MustCompile(`(?i)((^|[/\\])\.\.([/\\]|$)|%2e%2e|%2e\.|\.%2e)`)
)

var archiveExtractionTools = map[string]bool{
	"7z":           true,
	"7za":          true,
	"7zz":          true,
	"7zr":          true,
	"sevenz":       true,
	"sevenz-rust":  true,
	"sevenz-rust2": true,
	"tar":          true,
	"gtar":         true,
	"bsdtar":       true,
	"unzip":        true,
	"unrar":        true,
	"rar":          true,
	"cpio":         true,
	"pax":          true,
}

func detectArchiveTraversalHazard(cmdArgs []string) (bool, string) {
	if len(cmdArgs) == 0 {
		return false, ""
	}

	candidates, exceeded := policy.UnwrapCommands(cmdArgs)
	if exceeded {
		return true, "deeply nested wrapper chain around command invocation"
	}

	for _, cand := range candidates {
		canon := policy.CanonicalizeCommand(cand)
		if len(canon) == 0 {
			continue
		}
		tool := strings.ToLower(policy.NormalizeBinaryName(canon[0]))
		if !archiveExtractionTools[tool] {
			continue
		}

		args := canon[1:]
		for i := 0; i < len(args); i++ {
			arg := args[i]
			lower := strings.ToLower(arg)

			// 1. Unsafe archive extraction flags allowing absolute paths or symlink escapes (Zip-Slip / GHSA-qh76-45cr-8xrc)
			if arg == "-P" || lower == "--absolute-names" ||
				lower == "--keep-directory-symlink" || lower == "--dereference" ||
				lower == "-spe" || lower == "-snl" || lower == "-snh" {
				return true, fmt.Sprintf("unsafe archive extraction flag %q on %s (Zip-Slip defense)", arg, tool)
			}

			// 2. Direct path traversal or encoded traversal segments anywhere in archive invocation
			if reZipSlipTraversal.MatchString(arg) {
				return true, fmt.Sprintf("archive path traversal segment detected in %s argument %q (Zip-Slip defense)", tool, arg)
			}

			// 3. Absolute extraction destination targets (-o/..., -C /..., --directory=/..., -d /...)
			var destTarget string
			switch {
			case strings.HasPrefix(lower, "-o") && len(arg) > 2 && strings.HasPrefix(tool, "7z"):
				destTarget = arg[2:]
			case strings.HasPrefix(lower, "--directory="):
				destTarget = arg[len("--directory="):]
			case (arg == "-C" || arg == "--directory" || arg == "-d") && i+1 < len(args):
				destTarget = args[i+1]
			}

			if destTarget != "" {
				if strings.HasPrefix(destTarget, "/") || strings.HasPrefix(destTarget, "\\") ||
					(len(destTarget) >= 2 && destTarget[1] == ':') || reZipSlipTraversal.MatchString(destTarget) {
					return true, fmt.Sprintf("out-of-workspace archive extraction target %q on %s (Zip-Slip defense)", destTarget, tool)
				}
			}
		}
	}

	return false, ""
}

// DetectAmbiguousParameters inspects command arguments for subshell injection,
// differential fuzzing payloads, archive Zip-Slip hazards, or inline network/eval execution
// that warrant Tier 2 hardware isolation.
func DetectAmbiguousParameters(cmdArgs []string) (bool, string) {
	if len(cmdArgs) == 0 {
		return false, ""
	}

	totalLen := 0
	for _, arg := range cmdArgs {
		totalLen += len(arg)
		if reSubshellChaining.MatchString(arg) {
			return true, "embedded subshell or command chaining detected in command arguments"
		}
		if reFuzzingAnomalies.MatchString(arg) {
			return true, "fuzzing payload anomaly or memory inspection pattern detected"
		}
	}

	if totalLen > 4096 {
		return true, fmt.Sprintf("argument vector size (%d bytes) exceeds Tier 1 fast-path threshold (>4096)", totalLen)
	}

	if isArchiveHazard, reason := detectArchiveTraversalHazard(cmdArgs); isArchiveHazard {
		return true, reason
	}

	fullCmd := strings.Join(cmdArgs, " ")
	if reInlineEvalNet.MatchString(fullCmd) {
		return true, "inline script execution with embedded network/eval primitives"
	}

	return false, ""
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
		} else if !opts.Airgap && selectedTier == policy.Tier1 {
			// Dynamic Tier Escalation:
			// If arguments contain ambiguous subshell chaining, differential fuzzing payloads (ARTEX/PentAGI),
			// or inline network execution, escalate from Tier 1 to Tier 2 (Aegisbox MicroVM) for hardware isolation.
			if isAmbiguous, reason := DetectAmbiguousParameters(cmdArgs); isAmbiguous {
				selectedTier = policy.Tier2
				matchReason = fmt.Sprintf("dynamic tier escalation: %s (escalated to Tier 2 Aegisbox MicroVM for hardware isolation)", reason)
			}
		}
	}

	// 3. Resolve target engine binary and build invocation arguments
	var targetEngine string
	var binPath string
	var execArgs []string

	// Build effective command args, wrapping build commands with soulcaster if enabled by policy.
	// When EnforceHermetic is active, fail closed if --no-attestation is passed or soulcaster is missing.
	needsAttest := pol.ShouldAttest(cmdArgs) || (pol.Attestation == nil && isBuildCommand(cmdArgs))
	enforceHermetic := pol.Attestation != nil && pol.Attestation.Enabled && pol.Attestation.EnforceHermetic

	effectiveCmdArgs := cmdArgs
	if needsAttest {
		if opts.NoAttestation {
			if enforceHermetic {
				return nil, errors.New("hermetic build attestation enforced by policy (enforce_hermetic: true); --no-attestation bypass is forbidden")
			}
		} else {
			soulcasterBin, err := FindExecutable("soulcaster")
			if err != nil || soulcasterBin == "" {
				if enforceHermetic {
					return nil, fmt.Errorf("hermetic build attestation enforced by policy (enforce_hermetic: true), but soulcaster binary is unavailable: %w", err)
				}
			} else if len(cmdArgs) > 0 && policy.NormalizeBinaryName(cmdArgs[0]) != "soulcaster" {
				effectiveCmdArgs = append([]string{"soulcaster", "wrap", "--"}, cmdArgs...)
			}
		}
	}

	// 3-State Optional Pillar enforcement (Shield & Stormcage).
	// State 3 (explicitly required in fabrial.yaml but missing on PATH) MUST fail closed (exit 126).
	pillarResolver := opts.PillarResolver
	if pillarResolver == nil {
		pillarResolver = pillars.DefaultResolver()
	}
	pillarReq := pillars.RequirementsFromPolicy(pol)
	shieldRes := pillarResolver.ResolveShield(pillarReq)
	if shieldRes.State == pillars.StateRequiredMissing {
		return nil, shieldRes.Err
	}
	stormcageRes := pillarResolver.ResolveStormcage(pillarReq)
	if stormcageRes.State == pillars.StateRequiredMissing {
		return nil, stormcageRes.Err
	}

	// Shield in-flight secret wire guard environment injection
	shieldCfg := pol.GetShieldConfig()
	shieldExplicit := opts.Shield || pol.RequireShield || (pol.Shield != nil && pol.Shield.Enabled)
	shieldActive := shieldRes.IsActive()
	shieldEnvOverride := os.Getenv("SHIELD_PROXY_ADDR") != ""
	var injectedEnv []string
	if (shieldActive || shieldExplicit || shieldEnvOverride) && (opts.Net || opts.Shield || (shieldActive && shieldCfg.Enabled && shieldCfg.AutoInjectEnv && opts.Net)) {
		if addr, ok := DetectShieldProxy(shieldCfg.ProxyAddr); ok {
			injectedEnv = append(injectedEnv,
				"HTTP_PROXY=http://"+addr,
				"HTTPS_PROXY=http://"+addr,
				"http_proxy=http://"+addr,
				"https_proxy=http://"+addr,
				"SOVEREIGN_SHIELD_ACTIVE=1",
			)
		} else if pol.RequireShield && (opts.Net || opts.Shield) {
			return nil, pillars.NewRequiredUnhealthyError(pillars.Shield, "wire guard proxy offline (fail-closed)")
		} else if (shieldExplicit || shieldActive) && shieldCfg.FailClosed && (opts.Net || opts.Shield) {
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

	// Bound concurrent Tier 2 microVM launches across N subagents via cross-process flock queue
	if dec.Tier == policy.Tier2 {
		q := getTier2ExecutionQueue()
		reqID := fmt.Sprintf("exec-%d-%d", os.Getpid(), tier2ReqSeq.Add(1))
		subtask := ""
		if dec.Options != nil {
			subtask = dec.Options.SubagentTask
		}
		lease, err := q.AcquireSlot(ctx, queue.WorkloadRequest{
			SessionID: reqID,
			SubtaskID: subtask,
			Command:   dec.Command,
		})
		if err != nil {
			return 1, fmt.Errorf("fabrial: Tier 2 microVM queue rejected workload: %w", err)
		}
		defer lease.Release()
	}

	cmd := exec.CommandContext(ctx, dec.BinaryPath, dec.ExecArgs...)
	procident.ConfigureChildProcGroup(cmd)
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

// FindExecutable searches for a binary across trusted Homebrew/system prefixes and absolute
// PATH directories, enforcing Layer 1 (zero-execution Go debug/buildinfo provenance for all
// bonjoski ecosystem binaries) and Layer 2 (regular executable, non-world-writable binary and
// parent dir, UID ownership, canonical EvalSymlinks path).
func FindExecutable(name string) (string, error) {
	return pillars.LookupExecutable(name)
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
// Recursively unpeels wrappers (env, command, nohup, nice, timeout, stdbuf, xargs, sh/bash/zsh -c),
// normalizes versioned binaries, and strips global flags to defeat evasion.
func isBuildCommand(cmdArgs []string) bool {
	if len(cmdArgs) == 0 {
		return false
	}

	candidates, exceeded := policy.UnwrapCommands(cmdArgs)
	if exceeded {
		return true
	}

	for _, cand := range candidates {
		canon := policy.CanonicalizeCommand(cand)
		if len(canon) == 0 {
			continue
		}
		tool := canon[0]
		switch tool {
		case "make", "cmake", "ninja", "gcc", "g++", "clang", "clang++", "rustc":
			return true
		case "go":
			if len(canon) >= 2 {
				sub := canon[1]
				if sub == "build" || sub == "install" {
					return true
				}
				if sub == "test" {
					for _, a := range canon[2:] {
						if a == "-c" || strings.HasPrefix(a, "-c=") {
							return true
						}
					}
				}
			}
		case "cargo":
			if len(canon) >= 2 && (canon[1] == "build" || canon[1] == "check") {
				return true
			}
		}
	}

	return false
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
	hasPreferred := false
	for _, p := range preferred {
		if p != "" {
			candidates = append(candidates, p)
			hasPreferred = true
		}
	}
	if !hasPreferred {
		candidates = append(candidates, "127.0.0.1:8443", "127.0.0.1:8080")
	}
	for _, addr := range candidates {
		conn, err := net.DialTimeout("tcp", addr, 150*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return addr, true
		}
	}
	return "", false
}
