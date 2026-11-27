package topui

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	_ "modernc.org/sqlite"

	"github.com/bonjoski/fabrial/pkg/doctor"
	"github.com/bonjoski/fabrial/pkg/session"
)

const (
	// DefaultProviderTimeout enforces a strict 500ms per-source poll ceiling.
	DefaultProviderTimeout = 500 * time.Millisecond
	// MaxDirScanEntries caps directory scans (traces, receipts, worktrees) against DoS.
	MaxDirScanEntries = 50
	// MaxTracePreviewBytes caps per-trace event preview parsing at 512 KiB.
	MaxTracePreviewBytes = 512 * 1024
	// MaxSocketResponseBytes caps local socket read payloads at 512 KiB.
	MaxSocketResponseBytes = 512 * 1024
)

var (
	safeTicketIDRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)
	safeTraceIDRe  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
)

// CollectorConfig configures all local read-only state sources for fabrial-top.
type CollectorConfig struct {
	Workdir         string
	HomeDir         string
	FabrialSock     string
	SessionsFile    string
	ReceiptsDir     string
	LocksmithSock   string
	CoppermindDBs   []string
	TinmindDir      string
	FlightdeckDir   string
	OathgateDB      string
	ProviderTimeout time.Duration
	SkipDoctor      bool
	DoctorInspector *doctor.Inspector
}

// DefaultCollectorConfig builds standard local workstation paths under the user's home directory.
func DefaultCollectorConfig(workdir string) CollectorConfig {
	if workdir == "" {
		workdir = "."
	}
	home, _ := os.UserHomeDir()
	cfg := CollectorConfig{
		Workdir:         workdir,
		HomeDir:         home,
		ProviderTimeout: DefaultProviderTimeout,
	}
	if home != "" {
		cfg.FabrialSock = filepath.Join(home, ".fabrial", "fabrial.sock")
		cfg.SessionsFile = filepath.Join(home, ".fabrial", "sessions.json")
		// Dial locksmithd.sock directly (the real non-symlink UDS created by locksmith daemon).
		cfg.LocksmithSock = filepath.Join(home, ".locksmith", "locksmithd.sock")
		cfg.CoppermindDBs = []string{
			filepath.Join(home, ".coppermind", "projects", "github", "coppermind.db"),
			filepath.Join(home, ".coppermind", "coppermind.db"),
		}
		cfg.TinmindDir = filepath.Join(home, ".tinmind", "traces")
		cfg.FlightdeckDir = filepath.Join(home, ".flightdeck", "traces")
		cfg.OathgateDB = filepath.Join(home, ".oathgate", "ledger.db")
	}
	cfg.ReceiptsDir = filepath.Join(workdir, ".fabrial", "receipts")
	if envSock := os.Getenv("FABRIAL_SOCKET"); envSock != "" {
		cfg.FabrialSock = envSock
	}
	if envSock := os.Getenv("LOCKSMITH_SOCKET"); envSock != "" {
		cfg.LocksmithSock = envSock
	}
	return cfg
}

// sqliteReadOnlyDSN builds a strictly read-only SQLite URI so N=8 parallel writers
// never experience SQLITE_BUSY or WAL lock contention.
func sqliteReadOnlyDSN(dbPath string) string {
	slashed := filepath.ToSlash(dbPath)
	// Preserve leading slash on Unix while encoding spaces/special characters safely.
	parts := strings.Split(slashed, "/")
	for i, p := range parts {
		if i == 0 && len(p) == 2 && p[1] == ':' {
			// Preserve Windows drive prefix (e.g. C:).
			continue
		}
		parts[i] = url.PathEscape(p)
	}
	encoded := strings.Join(parts, "/")
	if !strings.HasPrefix(encoded, "/") {
		encoded = "/" + encoded
	}
	return "file:" + encoded + "?mode=ro&_busy_timeout=200"
}

// collectWorktrees enumerates git worktrees and bounded dirty file counts.
func collectWorktrees(ctx context.Context, workdir string) ([]WorktreeStatus, ProviderStatus) {
	start := time.Now()
	status := ProviderStatus{Name: "git-worktrees"}
	defer func() { status.LatencyMs = time.Since(start).Milliseconds() }()

	if _, err := exec.LookPath("git"); err != nil {
		status.State = ProviderOffline
		status.Detail = "git binary not installed"
		return nil, status
	}

	cmd := exec.CommandContext(ctx, "git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", workdir, "worktree", "list", "--porcelain")
	out, err := cmd.Output()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			status.State = ProviderTimeout
			status.Detail = "git worktree list timed out"
			return nil, status
		}
		status.State = ProviderOffline
		status.Detail = "not inside a git repository"
		status.Hint = "Run fabrial-top inside a git repository or pass --dir <repo>"
		return nil, status
	}

	worktrees := parseGitWorktreePorcelain(string(out))
	if len(worktrees) > MaxDirScanEntries {
		worktrees = worktrees[:MaxDirScanEntries]
	}

	// Best-effort dirty count for up to 16 non-bare worktrees within remaining ctx budget.
	for i := 0; i < len(worktrees) && i < 16; i++ {
		if ctx.Err() != nil || worktrees[i].Bare {
			break
		}
		stCmd := exec.CommandContext(ctx, "git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", worktrees[i].Path, "status", "--porcelain")
		stOut, stErr := stCmd.Output()
		if stErr == nil {
			lines := bytes.Split(bytes.TrimSpace(stOut), []byte("\n"))
			if len(lines) == 1 && len(lines[0]) == 0 {
				worktrees[i].DirtyFiles = 0
			} else {
				worktrees[i].DirtyFiles = len(lines)
			}
		}
	}

	status.State = ProviderOK
	status.Detail = fmt.Sprintf("%d worktree(s)", len(worktrees))
	return worktrees, status
}

// parseGitWorktreePorcelain parses `git worktree list --porcelain` output deterministically.
func parseGitWorktreePorcelain(raw string) []WorktreeStatus {
	var result []WorktreeStatus
	var cur *WorktreeStatus

	flush := func() {
		if cur != nil && cur.Path != "" {
			if cur.Branch == "" {
				if cur.Bare {
					cur.Branch = "(bare)"
				} else if cur.Detached {
					cur.Branch = "(detached)"
				}
			}
			result = append(result, *cur)
		}
		cur = nil
	}

	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		switch {
		case strings.HasPrefix(line, "worktree "):
			flush()
			cur = &WorktreeStatus{Path: strings.TrimPrefix(line, "worktree ")}
		case cur == nil:
			continue
		case strings.HasPrefix(line, "HEAD "):
			sha := strings.TrimPrefix(line, "HEAD ")
			if len(sha) > 12 {
				sha = sha[:12]
			}
			cur.HeadSHA = sha
		case strings.HasPrefix(line, "branch "):
			br := strings.TrimPrefix(line, "branch ")
			br = strings.TrimPrefix(br, "refs/heads/")
			cur.Branch = br
		case line == "bare":
			cur.Bare = true
		case line == "detached":
			cur.Detached = true
		case strings.HasPrefix(line, "locked"):
			cur.Locked = true
		}
	}
	flush()
	return result
}

// collectSessions reads local Fabrial session metadata (read-only, zero secrets)
// and probes ~/.fabrial/fabrial.sock health under ctx deadline.
func collectSessions(ctx context.Context, sessionsFile, fabrialSock, receiptsDir string) ([]AgentSessionStatus, ProviderStatus) {
	start := time.Now()
	status := ProviderStatus{Name: "fabrial-sessions"}
	defer func() { status.LatencyMs = time.Since(start).Milliseconds() }()

	// Optional bounded health check on fabrial.sock if present.
	daemonUp := false
	if fabrialSock != "" {
		if _, statErr := os.Lstat(fabrialSock); statErr == nil {
			if err := probeFabrialHealthSocket(ctx, fabrialSock); err != nil {
				if errors.Is(err, ErrSymlinkRejected) || errors.Is(err, ErrForeignUID) || errors.Is(err, ErrInsecureSocket) {
					status.State = ProviderError
					status.Detail = err.Error()
					return nil, status
				}
				if errors.Is(ctx.Err(), context.DeadlineExceeded) || isNetTimeout(err) {
					status.State = ProviderTimeout
					status.Detail = "fabrial.sock health probe timed out"
					return nil, status
				}
			} else {
				daemonUp = true
			}
		}
	}

	receiptCounts := countReceiptsBySession(receiptsDir)

	if sessionsFile == "" {
		status.State = ProviderOffline
		status.Detail = "no sessions path configured"
		return nil, status
	}

	if err := VerifyRegularFileOwned(sessionsFile); err != nil {
		if os.IsNotExist(err) {
			status.State = ProviderOK
			if daemonUp {
				status.Detail = "daemon online, 0 active sessions"
			} else {
				status.Detail = "0 active sessions"
			}
			status.Hint = "Run `fabrial session begin` to start an ambient session"
			return nil, status
		}
		if errors.Is(err, ErrSymlinkRejected) || errors.Is(err, ErrForeignUID) {
			status.State = ProviderError
			status.Detail = err.Error()
			return nil, status
		}
		status.State = ProviderOffline
		status.Detail = "sessions store unavailable"
		return nil, status
	}

	data, err := os.ReadFile(sessionsFile)
	if err != nil {
		status.State = ProviderError
		status.Detail = fmt.Sprintf("read sessions: %v", err)
		return nil, status
	}

	// Unmarshal into a narrow non-secret projection struct so MasterToken and raw
	// environment secrets are never retained in memory or serialized.
	var rawSessions map[string]struct {
		ID          string            `json:"session_id"`
		ParentID    string            `json:"parent_id"`
		SubtaskID   string            `json:"subtask_id"`
		Scopes      []string          `json:"scopes"`
		CreatedAt   time.Time         `json:"created_at"`
		ExpiresAt   time.Time         `json:"expires_at"`
		Revoked     bool              `json:"revoked"`
		IsMaster    bool              `json:"is_master"`
		PID         int               `json:"pid"`
		StartTimeNs int64             `json:"start_time_ns"`
		Environment map[string]string `json:"environment"`
	}
	if err := json.Unmarshal(data, &rawSessions); err != nil {
		status.State = ProviderError
		status.Detail = "malformed sessions.json"
		return nil, status
	}

	now := time.Now()
	sessions := make([]AgentSessionStatus, 0, len(rawSessions))
	for key, g := range rawSessions {
		id := g.ID
		if id == "" {
			id = key
		}
		if !session.ValidateSessionID(id) {
			continue
		}
		rem := int64(time.Until(g.ExpiresAt).Seconds())
		if rem < 0 {
			rem = 0
		}
		// Skip sessions expired more than 24h ago to keep the table signal-rich.
		if now.Sub(g.ExpiresAt) > 24*time.Hour {
			continue
		}
		ws := ""
		if g.Environment != nil {
			ws = g.Environment["FABRIAL_WORKSPACE"]
		}
		sessions = append(sessions, AgentSessionStatus{
			SessionID:    id,
			ParentID:     g.ParentID,
			SubtaskID:    g.SubtaskID,
			Workspace:    ws,
			Scopes:       append([]string(nil), g.Scopes...),
			IsMaster:     g.IsMaster,
			PID:          g.PID,
			StartTimeNs:  g.StartTimeNs,
			CreatedAt:    g.CreatedAt,
			ExpiresAt:    g.ExpiresAt,
			RemainingSec: rem,
			Revoked:      g.Revoked,
			ReceiptCount: receiptCounts[id],
		})
	}

	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].CreatedAt.After(sessions[j].CreatedAt)
	})
	if len(sessions) > MaxDirScanEntries {
		sessions = sessions[:MaxDirScanEntries]
	}

	status.State = ProviderOK
	if daemonUp {
		status.Detail = fmt.Sprintf("daemon online, %d session(s)", len(sessions))
	} else {
		status.Detail = fmt.Sprintf("%d session(s)", len(sessions))
	}
	return sessions, status
}

func probeFabrialHealthSocket(ctx context.Context, socketPath string) error {
	conn, err := DialOwnedUnixSocket(ctx, socketPath)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	tr := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return conn, nil
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/health", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected health status %d", resp.StatusCode)
	}
	return nil
}

func countReceiptsBySession(receiptsDir string) map[string]int {
	counts := make(map[string]int)
	if receiptsDir == "" {
		return counts
	}
	if err := VerifyDirOwned(receiptsDir); err != nil {
		return counts
	}
	entries, err := os.ReadDir(receiptsDir)
	if err != nil {
		return counts
	}
	for i, e := range entries {
		if i >= MaxDirScanEntries {
			break
		}
		if !e.IsDir() {
			continue
		}
		subDir := filepath.Join(receiptsDir, e.Name())
		if VerifyDirOwned(subDir) != nil {
			continue
		}
		files, err := os.ReadDir(subDir)
		if err != nil {
			continue
		}
		n := 0
		for _, f := range files {
			if !f.IsDir() && strings.HasSuffix(f.Name(), ".json") {
				n++
			}
		}
		if n > 0 {
			counts[e.Name()] = n
		}
	}
	return counts
}

// collectLocksmithLeases queries Locksmith's read-only list_leases IPC action.
// INVARIANT: Never triggers Touch ID and never calls get / request_lease.
func collectLocksmithLeases(ctx context.Context, socketPath string) ([]LeaseMetaStatus, ProviderStatus) {
	start := time.Now()
	status := ProviderStatus{Name: "locksmith-leases"}
	defer func() { status.LatencyMs = time.Since(start).Milliseconds() }()

	if socketPath == "" {
		status.State = ProviderOffline
		status.Detail = "locksmith socket not configured"
		return nil, status
	}

	if _, err := os.Lstat(socketPath); err != nil {
		if os.IsNotExist(err) {
			status.State = ProviderOffline
			status.Detail = "locksmith daemon offline"
			status.Hint = "Run `locksmith daemon start` to enable ephemeral leases"
			return nil, status
		}
		status.State = ProviderError
		status.Detail = err.Error()
		return nil, status
	}

	conn, err := DialOwnedUnixSocket(ctx, socketPath)
	if err != nil {
		if errors.Is(err, ErrSymlinkRejected) || errors.Is(err, ErrForeignUID) || errors.Is(err, ErrInsecureSocket) {
			status.State = ProviderError
			status.Detail = err.Error()
			return nil, status
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || isNetTimeout(err) {
			status.State = ProviderTimeout
			status.Detail = "locksmith socket timed out"
			return nil, status
		}
		status.State = ProviderOffline
		status.Detail = "locksmith daemon unreachable"
		status.Hint = "Run `locksmith daemon start`"
		return nil, status
	}
	defer func() { _ = conn.Close() }()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	reqPayload := []byte(`{"action":"list_leases"}`)
	if _, err := conn.Write(reqPayload); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || isNetTimeout(err) {
			status.State = ProviderTimeout
			status.Detail = "locksmith write timed out"
			return nil, status
		}
		status.State = ProviderError
		status.Detail = fmt.Sprintf("locksmith write failed: %v", err)
		return nil, status
	}

	// Read strictly bounded metadata response; LeaseMetaStatus physically has no Value field.
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Leases []struct {
			LeaseID          string    `json:"lease_id"`
			SecretName       string    `json:"secret_name"`
			ClientPID        int       `json:"client_pid"`
			ProcessStartTime int64     `json:"process_start_time"`
			SpiffeID         string    `json:"spiffe_id"`
			CreatedAt        time.Time `json:"created_at"`
			ExpiresAt        time.Time `json:"expires_at"`
			MaxUses          int       `json:"max_uses"`
			UsesCount        int       `json:"uses_count"`
			Revoked          bool      `json:"revoked"`
		} `json:"leases"`
	}

	dec := json.NewDecoder(io.LimitReader(conn, MaxSocketResponseBytes))
	if err := dec.Decode(&resp); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || isNetTimeout(err) {
			status.State = ProviderTimeout
			status.Detail = "locksmith response timed out"
			return nil, status
		}
		status.State = ProviderError
		status.Detail = "invalid locksmith list_leases response"
		return nil, status
	}

	leases := make([]LeaseMetaStatus, 0, len(resp.Leases))
	for _, l := range resp.Leases {
		rem := int64(time.Until(l.ExpiresAt).Seconds())
		if rem < 0 {
			rem = 0
		}
		leases = append(leases, LeaseMetaStatus{
			LeaseID:          l.LeaseID,
			SecretName:       l.SecretName,
			ClientPID:        l.ClientPID,
			ProcessStartTime: l.ProcessStartTime,
			SpiffeID:         l.SpiffeID,
			CreatedAt:        l.CreatedAt,
			ExpiresAt:        l.ExpiresAt,
			RemainingSec:     rem,
			MaxUses:          l.MaxUses,
			UsesCount:        l.UsesCount,
			Revoked:          l.Revoked,
		})
	}
	if len(leases) > MaxDirScanEntries {
		leases = leases[:MaxDirScanEntries]
	}

	status.State = ProviderOK
	status.Detail = fmt.Sprintf("%d active lease(s)", len(leases))
	return leases, status
}

// collectCoppermindInbox opens Coppermind SQLite WAL strictly in read-only mode
// to read pending commit-lens inbox tickets and open high/critical observations.
func collectCoppermindInbox(ctx context.Context, dbPaths []string) ([]LensTicketSummary, int, ProviderStatus) {
	start := time.Now()
	status := ProviderStatus{Name: "coppermind-inbox"}
	defer func() { status.LatencyMs = time.Since(start).Milliseconds() }()

	var activePath string
	for _, p := range dbPaths {
		if p == "" {
			continue
		}
		if err := VerifyRegularFileOwned(p); err != nil {
			if errors.Is(err, ErrSymlinkRejected) || errors.Is(err, ErrForeignUID) {
				status.State = ProviderError
				status.Detail = err.Error()
				return nil, 0, status
			}
			continue
		}
		fi, err := os.Lstat(p)
		if err != nil || fi.Size() == 0 {
			continue
		}
		activePath = p
		break
	}

	if activePath == "" {
		status.State = ProviderOffline
		status.Detail = "coppermind database not found"
		status.Hint = "Install coppermind and run `coppermind init` to enable lens inbox tracking"
		return nil, 0, status
	}

	db, err := sql.Open("sqlite", sqliteReadOnlyDSN(activePath))
	if err != nil {
		status.State = ProviderError
		status.Detail = fmt.Sprintf("open coppermind db: %v", err)
		return nil, 0, status
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)

	tickets := make([]LensTicketSummary, 0)
	rows, err := db.QueryContext(ctx, `
		SELECT id, lens_name, commit_sha, memory_id, repo_name, branch_name, summary, status, created_at
		FROM pending_lens_tickets
		WHERE status = 'pending'
		ORDER BY created_at DESC
		LIMIT ?`, MaxDirScanEntries)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			status.State = ProviderTimeout
			status.Detail = "coppermind query timed out"
			return nil, 0, status
		}
		// Older Coppermind DB without pending_lens_tickets table degrades gracefully.
		if !strings.Contains(err.Error(), "no such table") {
			status.State = ProviderError
			status.Detail = fmt.Sprintf("query pending_lens_tickets: %v", err)
			return nil, 0, status
		}
	} else {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var t LensTicketSummary
			var createdUnix int64
			if scanErr := rows.Scan(&t.ID, &t.LensName, &t.CommitSHA, &t.MemoryID, &t.RepoName, &t.BranchName, &t.Summary, &t.Status, &createdUnix); scanErr != nil {
				continue
			}
			if createdUnix > 0 {
				t.CreatedAt = parseFlexibleUnixTime(createdUnix)
			}
			t.TriageCmd = FormatLensTriageCmd(t)
			tickets = append(tickets, t)
		}
	}

	openHigh := 0
	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM memory_nodes
		WHERE derived = 1
		  AND LOWER(status) = 'open'
		  AND LOWER(severity) IN ('high', 'critical')`).Scan(&count); err == nil {
		openHigh = count
	}

	status.State = ProviderOK
	status.Detail = fmt.Sprintf("%d pending ticket(s), %d open high obs", len(tickets), openHigh)
	return tickets, openHigh, status
}

// FormatLensTriageCmd returns a shell-safe Coppermind lens triage command for a ticket.
// Untrusted ticket IDs or lens names that violate strict allowlist regexes fall back safely.
func FormatLensTriageCmd(t LensTicketSummary) string {
	id := strings.TrimSpace(t.ID)
	lens := strings.TrimSpace(t.LensName)
	if safeTicketIDRe.MatchString(id) && safeTicketIDRe.MatchString(lens) {
		return fmt.Sprintf("coppermind --project github lens prepare --lens %s --ticket %s", lens, id)
	}
	if safeTicketIDRe.MatchString(lens) {
		return fmt.Sprintf("coppermind --project github lens prepare --lens %s", lens)
	}
	return "coppermind --project github inbox list"
}

// collectTraces scans ~/.tinmind/traces and ~/.flightdeck/traces (capped at 50 newest files).
func collectTraces(ctx context.Context, tinmindDir, flightdeckDir string) ([]TraceSummary, ProviderStatus) {
	start := time.Now()
	status := ProviderStatus{Name: "tinmind-traces"}
	defer func() { status.LatencyMs = time.Since(start).Milliseconds() }()

	type traceCandidate struct {
		source  string
		path    string
		name    string
		modTime time.Time
		size    int64
	}

	dirs := []struct {
		source string
		dir    string
	}{
		{"tinmind", tinmindDir},
		{"flightdeck", flightdeckDir},
	}

	var candidates []traceCandidate
	foundAnyDir := false
	for _, d := range dirs {
		if d.dir == "" {
			continue
		}
		if err := VerifyDirOwned(d.dir); err != nil {
			if errors.Is(err, ErrSymlinkRejected) || errors.Is(err, ErrForeignUID) {
				status.State = ProviderError
				status.Detail = err.Error()
				return nil, status
			}
			continue
		}
		foundAnyDir = true
		entries, err := os.ReadDir(d.dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if ctx.Err() != nil {
				status.State = ProviderTimeout
				status.Detail = "trace directory scan timed out"
				return nil, status
			}
			name := e.Name()
			if e.IsDir() || (!strings.HasSuffix(name, ".jsonl") && !strings.HasSuffix(name, ".jsonl.zst")) {
				continue
			}
			fullPath := filepath.Join(d.dir, name)
			fi, lErr := os.Lstat(fullPath)
			if lErr != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
				continue
			}
			candidates = append(candidates, traceCandidate{
				source:  d.source,
				path:    fullPath,
				name:    name,
				modTime: fi.ModTime(),
				size:    fi.Size(),
			})
		}
	}

	if !foundAnyDir {
		status.State = ProviderOffline
		status.Detail = "tinmind / flightdeck not initialized"
		status.Hint = "Install tinmind (`brew install bonjoski/tap/tinmind`) to record local agent traces"
		return nil, status
	}

	// Sort newest-first and cap strictly to 50 files before parsing any trace content.
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].modTime.After(candidates[j].modTime)
	})
	if len(candidates) > MaxDirScanEntries {
		candidates = candidates[:MaxDirScanEntries]
	}

	traces := make([]TraceSummary, 0, len(candidates))
	for _, c := range candidates {
		if ctx.Err() != nil {
			break
		}
		format := "jsonl"
		traceID := strings.TrimSuffix(c.name, ".jsonl")
		if strings.HasSuffix(c.name, ".jsonl.zst") {
			format = "zstd"
			traceID = strings.TrimSuffix(c.name, ".jsonl.zst")
		}
		evCount, failCount, lastCmd := previewTraceFile(c.path, format)
		replayCmd := "tinmind replay --safe-ansi " + traceID
		if !safeTraceIDRe.MatchString(traceID) {
			replayCmd = "tinmind list"
		}
		traces = append(traces, TraceSummary{
			TraceID:       traceID,
			Source:        c.source,
			Format:        format,
			FilePath:      c.path,
			SizeBytes:     c.size,
			ModTime:       c.modTime,
			EventCount:    evCount,
			FailureCount:  failCount,
			LastCommand:   lastCmd,
			ReplayCommand: replayCmd,
		})
	}

	status.State = ProviderOK
	status.Detail = fmt.Sprintf("%d trace(s)", len(traces))
	return traces, status
}

func previewTraceFile(path, format string) (events, failures int, lastCmd string) {
	if err := VerifyRegularFileOwned(path); err != nil {
		return 0, 0, ""
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, ""
	}
	defer func() { _ = f.Close() }()

	var r io.Reader = io.LimitReader(f, MaxTracePreviewBytes)
	if format == "zstd" {
		dec, zErr := zstd.NewReader(f)
		if zErr != nil {
			return 0, 0, ""
		}
		defer dec.Close()
		r = io.LimitReader(dec, MaxTracePreviewBytes)
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		events++
		var ev struct {
			Type     string `json:"type"`
			Command  string `json:"command"`
			Tool     string `json:"tool"`
			ExitCode *int   `json:"exit_code"`
		}
		if json.Unmarshal(line, &ev) != nil {
			continue
		}
		if ev.Type == "finding" {
			failures++
		}
		if ev.ExitCode != nil && *ev.ExitCode != 0 {
			failures++
		}
		if ev.Command != "" {
			lastCmd = ev.Command
		} else if ev.Tool != "" {
			lastCmd = ev.Tool
		}
	}
	return events, failures, lastCmd
}

// collectOathgateCheckpoints opens ~/.oathgate/ledger.db strictly in read-only mode.
func collectOathgateCheckpoints(ctx context.Context, dbPath string) ([]CheckpointSummary, ProviderStatus) {
	start := time.Now()
	status := ProviderStatus{Name: "oathgate-checkpoints"}
	defer func() { status.LatencyMs = time.Since(start).Milliseconds() }()

	if dbPath == "" {
		status.State = ProviderOffline
		status.Detail = "oathgate ledger not configured"
		return nil, status
	}
	if err := VerifyRegularFileOwned(dbPath); err != nil {
		if os.IsNotExist(err) {
			status.State = ProviderOffline
			status.Detail = "oathgate ledger not found"
			status.Hint = "Install oathgate (`brew install bonjoski/tap/oathgate`) and run `oathgate snap`"
			return nil, status
		}
		if errors.Is(err, ErrSymlinkRejected) || errors.Is(err, ErrForeignUID) {
			status.State = ProviderError
			status.Detail = err.Error()
			return nil, status
		}
		status.State = ProviderOffline
		status.Detail = "oathgate ledger unavailable"
		return nil, status
	}

	db, err := sql.Open("sqlite", sqliteReadOnlyDSN(dbPath))
	if err != nil {
		status.State = ProviderError
		status.Detail = fmt.Sprintf("open oathgate ledger: %v", err)
		return nil, status
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)

	rows, err := db.QueryContext(ctx, `
		SELECT id, parent_id, repo_root, worktree_id, label, trigger, git_head, git_branch,
		       cow_backend, duration_ms, entries_cloned, bytes_logical, pinned, tinmind_trace_id, created_at
		FROM snapshots
		ORDER BY created_at DESC
		LIMIT ?`, MaxDirScanEntries)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			status.State = ProviderTimeout
			status.Detail = "oathgate query timed out"
			return nil, status
		}
		if strings.Contains(err.Error(), "no such table") {
			status.State = ProviderOK
			status.Detail = "0 checkpoint(s)"
			return nil, status
		}
		status.State = ProviderError
		status.Detail = fmt.Sprintf("query oathgate snapshots: %v", err)
		return nil, status
	}
	defer func() { _ = rows.Close() }()

	var snaps []CheckpointSummary
	for rows.Next() {
		var c CheckpointSummary
		var pinned int
		var createdRaw string
		if scanErr := rows.Scan(
			&c.ID, &c.ParentID, &c.RepoRoot, &c.WorktreeID, &c.Label, &c.Trigger,
			&c.GitHead, &c.GitBranch, &c.CowBackend, &c.DurationMs, &c.EntriesCloned,
			&c.BytesLogical, &pinned, &c.TinmindTraceID, &createdRaw,
		); scanErr != nil {
			continue
		}
		c.Pinned = pinned != 0
		if ts, parseErr := time.Parse(time.RFC3339Nano, createdRaw); parseErr == nil {
			c.CreatedAt = ts
		} else if ts, parseErr := time.Parse(time.RFC3339, createdRaw); parseErr == nil {
			c.CreatedAt = ts
		}
		snaps = append(snaps, c)
	}

	status.State = ProviderOK
	status.Detail = fmt.Sprintf("%d checkpoint(s)", len(snaps))
	return snaps, status
}

// collectDoctorHealth reuses fabrial/pkg/doctor.Inspector with 3-state optional pillar discovery.
func collectDoctorHealth(ctx context.Context, insp *doctor.Inspector, workdir string) ([]PillarHealthSummary, ProviderStatus) {
	start := time.Now()
	status := ProviderStatus{Name: "fabrial-doctor"}
	defer func() { status.LatencyMs = time.Since(start).Milliseconds() }()

	if insp == nil {
		insp = doctor.NewInspector(400 * time.Millisecond)
	}
	reports := insp.InspectAll(ctx, workdir)
	out := make([]PillarHealthSummary, 0, len(reports))
	ready := 0
	for _, r := range reports {
		if r.Status == doctor.StatusReady || r.Status == doctor.StatusOnline {
			ready++
		}
		out = append(out, PillarHealthSummary{
			Pillar:     string(r.Pillar),
			Role:       r.Role,
			Status:     string(r.Status),
			Details:    r.Details,
			BinaryPath: r.BinaryPath,
			SocketPath: r.SocketPath,
			LatencyMs:  r.Latency.Milliseconds(),
			Required:   r.Required,
		})
	}
	status.State = ProviderOK
	status.Detail = fmt.Sprintf("%d/%d pillars healthy", ready, len(out))
	return out, status
}

func isNetTimeout(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// parseFlexibleUnixTime converts Unix seconds, milliseconds, microseconds, or nanoseconds
// safely into a JSON-marshalable UTC time.Time (clamping out-of-range years to zero).
func parseFlexibleUnixTime(v int64) time.Time {
	if v <= 0 {
		return time.Time{}
	}
	var ts time.Time
	switch {
	case v >= 1_000_000_000_000_000_000: // nanoseconds
		ts = time.Unix(0, v).UTC()
	case v >= 1_000_000_000_000_000: // microseconds
		ts = time.UnixMicro(v).UTC()
	case v >= 1_000_000_000_000: // milliseconds
		ts = time.UnixMilli(v).UTC()
	default: // seconds
		ts = time.Unix(v, 0).UTC()
	}
	if y := ts.Year(); y < 1 || y > 9999 {
		return time.Time{}
	}
	return ts
}
