package topui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bonjoski/fabrial/pkg/procident"
	"github.com/bonjoski/fabrial/pkg/session"
)

var (
	// ErrPIDRecycled is returned fail-closed when a target PID's kernel start time no longer matches.
	ErrPIDRecycled = errors.New("security violation: PID start time mismatch (possible PID reuse) — aborting terminate fail-closed")
	// ErrInvalidActionTarget is returned when an action identifier fails allowlist validation.
	ErrInvalidActionTarget = errors.New("invalid action target identifier")
	// ErrToolNotFound is returned when an external ecosystem binary is not installed on PATH.
	ErrToolNotFound = errors.New("required local tool not found on PATH")

	safeSnapIDRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

	allowedPillars = map[string]bool{
		"":           true,
		"airlock":    true,
		"locksmith":  true,
		"aegisbox":   true,
		"argus":      true,
		"conjoiner":  true,
		"soulcaster": true,
		"bomhound":   true,
		"halfshard":  true,
		"stormcage":  true,
	}
)

// LocalActionRunner executes explicitly confirmed, session-scoped local actions.
type LocalActionRunner struct {
	SessionsFile string
	Workdir      string

	// Overridable hooks for deterministic unit & adversarial testing.
	getStartTime func(pid int) (int64, error)
	signalProc   func(pid int) error
	lookPath     func(file string) (string, error)
	runCmd       func(cmd *exec.Cmd) error
}

// NewLocalActionRunner returns a production LocalActionRunner using kernel procident verification.
func NewLocalActionRunner(sessionsFile, workdir string) *LocalActionRunner {
	return &LocalActionRunner{
		SessionsFile: sessionsFile,
		Workdir:      workdir,
		getStartTime: procident.GetProcessStartTimeNs,
		signalProc:   killVerifiedProcessGroup,
		lookPath:     exec.LookPath,
		runCmd: func(cmd *exec.Cmd) error {
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Run()
		},
	}
}

// StopSession terminates ONLY the explicitly selected agent session after re-verifying
// its kernel (PID, ProcessStartTime) identity immediately before signaling.
func (r *LocalActionRunner) StopSession(ctx context.Context, sessionID string, pid int, startTime int64) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if sessionID != "" && !session.ValidateSessionID(sessionID) {
		return fmt.Errorf("%w: invalid session ID", ErrInvalidActionTarget)
	}

	// If a live PID is associated, strictly re-verify kernel start time before signaling.
	if pid > 0 {
		if pid == 1 || pid == os.Getpid() {
			return fmt.Errorf("%w: refusing to signal protected pid %d", ErrInvalidActionTarget, pid)
		}
		if startTime <= 0 {
			return fmt.Errorf("%w: missing expected process start time for pid %d", ErrPIDRecycled, pid)
		}
		getStart := r.getStartTime
		if getStart == nil {
			getStart = procident.GetProcessStartTimeNs
		}
		actualStart, err := getStart(pid)
		if err != nil {
			return fmt.Errorf("%w: failed to verify pid %d: %v", ErrPIDRecycled, pid, err)
		}
		if actualStart != startTime {
			return fmt.Errorf("%w: pid %d expected start=%d got start=%d", ErrPIDRecycled, pid, startTime, actualStart)
		}
		sigFn := r.signalProc
		if sigFn == nil {
			sigFn = killVerifiedProcessGroup
		}
		if err := sigFn(pid); err != nil {
			return fmt.Errorf("signal verified pid %d: %w", pid, err)
		}
	}

	// Scoped session revocation in sessions.json (never affects peer sessions).
	if sessionID != "" && r.SessionsFile != "" {
		if err := VerifyRegularFileOwned(r.SessionsFile); err == nil {
			sm := session.NewSessionManager()
			if loadErr := sm.LoadFromFile(r.SessionsFile); loadErr == nil {
				if revErr := sm.InvalidateSession(ctx, session.SessionID(sessionID)); revErr == nil {
					_ = sm.SaveToFile(r.SessionsFile)
				}
			}
		}
	}

	if pid <= 0 && sessionID == "" {
		return fmt.Errorf("%w: neither pid nor session_id provided", ErrInvalidActionTarget)
	}
	return nil
}

// BuildReplayCmd prepares a validated replay command preferring tinmind with flightdeck fallback.
func (r *LocalActionRunner) BuildReplayCmd(traceID string) (*exec.Cmd, error) {
	if !safeTraceIDRe.MatchString(traceID) || strings.Contains(traceID, "..") {
		return nil, fmt.Errorf("%w: unsafe trace ID %q", ErrInvalidActionTarget, CleanText(traceID))
	}
	lp := r.lookPath
	if lp == nil {
		lp = exec.LookPath
	}
	bin, err := lp("tinmind")
	if err != nil {
		bin, err = lp("flightdeck")
		if err != nil {
			return nil, fmt.Errorf("%w: neither tinmind nor flightdeck found on PATH", ErrToolNotFound)
		}
	}
	return exec.Command(bin, "replay", "--safe-ansi", traceID), nil
}

// LaunchReplay hands TTY execution to tinmind/flightdeck replay for traceID.
func (r *LocalActionRunner) LaunchReplay(traceID string) error {
	cmd, err := r.BuildReplayCmd(traceID)
	if err != nil {
		return err
	}
	return r.runCmd(cmd)
}

// BuildRewindCmd prepares a validated `oathgate diff` or `oathgate rewind` command.
func (r *LocalActionRunner) BuildRewindCmd(worktree, snapID string, diffOnly bool) (*exec.Cmd, error) {
	if !safeSnapIDRe.MatchString(snapID) || strings.Contains(snapID, "..") {
		return nil, fmt.Errorf("%w: unsafe checkpoint ID %q", ErrInvalidActionTarget, CleanText(snapID))
	}
	lp := r.lookPath
	if lp == nil {
		lp = exec.LookPath
	}
	bin, err := lp("oathgate")
	if err != nil {
		return nil, fmt.Errorf("%w: oathgate not found on PATH", ErrToolNotFound)
	}
	sub := "rewind"
	if diffOnly {
		sub = "diff"
	}
	cmd := exec.Command(bin, sub, snapID)
	if worktree != "" {
		if VerifyDirOwned(worktree) == nil {
			cmd.Dir = worktree
		}
	} else if r.Workdir != "" && VerifyDirOwned(r.Workdir) == nil {
		cmd.Dir = r.Workdir
	}
	return cmd, nil
}

// TriggerRewind hands TTY execution to `oathgate rewind <snapID>`.
func (r *LocalActionRunner) TriggerRewind(worktree, snapID string) error {
	cmd, err := r.BuildRewindCmd(worktree, snapID, false)
	if err != nil {
		return err
	}
	return r.runCmd(cmd)
}

// BuildDoctorFixCmd prepares a validated `fabrial doctor --fix` (or `fabrial fix <pillar>`) command.
func (r *LocalActionRunner) BuildDoctorFixCmd(pillar string) (*exec.Cmd, error) {
	p := strings.ToLower(strings.TrimSpace(pillar))
	if !allowedPillars[p] {
		return nil, fmt.Errorf("%w: unknown pillar %q", ErrInvalidActionTarget, CleanText(pillar))
	}
	bin, err := r.resolveFabrialBinary()
	if err != nil {
		return nil, err
	}
	if p == "" {
		return exec.Command(bin, "doctor", "--fix"), nil
	}
	return exec.Command(bin, "fix", p), nil
}

func (r *LocalActionRunner) resolveFabrialBinary() (string, error) {
	if exe, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(exe), "fabrial")
		if fi, sErr := os.Lstat(sibling); sErr == nil && fi.Mode()&os.ModeSymlink == 0 && fi.Mode().IsRegular() {
			return sibling, nil
		}
	}
	lp := r.lookPath
	if lp == nil {
		lp = exec.LookPath
	}
	bin, err := lp("fabrial")
	if err != nil {
		return "", fmt.Errorf("%w: fabrial binary not found", ErrToolNotFound)
	}
	return bin, nil
}

// copyToClipboardBestEffort copies text via local OS clipboard helper under a strict
// context deadline without failing or blocking if unavailable.
func copyToClipboardBestEffort(ctx context.Context, text string) bool {
	for _, candidate := range [][]string{
		{"pbcopy"},
		{"wl-copy"},
		{"xclip", "-selection", "clipboard"},
	} {
		bin, err := exec.LookPath(candidate[0])
		if err != nil {
			continue
		}
		cmd := exec.CommandContext(ctx, bin, candidate[1:]...)
		cmd.Stdin = strings.NewReader(text)
		if cmd.Run() == nil {
			return true
		}
	}
	return false
}
