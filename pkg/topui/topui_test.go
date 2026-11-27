package topui

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/klauspost/compress/zstd"
	_ "modernc.org/sqlite"
)

func TestParseGitWorktreePorcelain(t *testing.T) {
	raw := strings.Join([]string{
		"worktree /Users/dev/code/fabrial",
		"HEAD 5b4c67c1234567890abcdef",
		"branch refs/heads/main",
		"",
		"worktree /Users/dev/code/fabrial-wt2",
		"HEAD 99887766554433221100",
		"detached",
		"locked reason",
		"",
	}, "\n")

	wts := parseGitWorktreePorcelain(raw)
	if len(wts) != 2 {
		t.Fatalf("expected 2 worktrees, got %d", len(wts))
	}
	if wts[0].Branch != "main" || wts[0].HeadSHA != "5b4c67c12345" {
		t.Fatalf("unexpected primary worktree: %+v", wts[0])
	}
	if !wts[1].Detached || !wts[1].Locked || wts[1].Branch != "(detached)" {
		t.Fatalf("unexpected secondary worktree: %+v", wts[1])
	}
}

func TestCollectAllLocalSourcesEndToEnd(t *testing.T) {
	tmp := t.TempDir()

	// 1. Mock Locksmith read-only list_leases UDS server (Unix only).
	lockSock := ""
	if runtime.GOOS != "windows" {
		sockDir, err := os.MkdirTemp("/tmp", "ftop-")
		if err != nil {
			t.Fatalf("mkdirtemp sock: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
		lockSock = filepath.Join(sockDir, "locksmithd.sock")
		ln, err := net.Listen("unix", lockSock)
		if err != nil {
			t.Fatalf("listen locksmith mock: %v", err)
		}
		defer func() { _ = ln.Close() }()
		_ = os.Chmod(lockSock, 0600)
		go func() {
			for {
				conn, aErr := ln.Accept()
				if aErr != nil {
					return
				}
				go func(c net.Conn) {
					defer func() { _ = c.Close() }()
					buf := make([]byte, 4096)
					n, _ := c.Read(buf)
					var req struct {
						Action string `json:"action"`
					}
					_ = json.Unmarshal(buf[:n], &req)
					if req.Action != "list_leases" {
						_, _ = c.Write([]byte(`{"status":"ERROR","error":"unexpected action"}`))
						return
					}
					resp := map[string]any{
						"status": "OK",
						"leases": []map[string]any{
							{
								"lease_id":    "lease_01",
								"secret_name": "GITHUB_TOKEN",
								"client_pid":  1234,
								"created_at":  time.Now().Add(-10 * time.Second).UTC(),
								"expires_at":  time.Now().Add(5 * time.Minute).UTC(),
								"max_uses":    5,
								"uses_count":  1,
								"revoked":     false,
							},
						},
					}
					_ = json.NewEncoder(c).Encode(resp)
				}(conn)
			}
		}()
	}

	// 2. Coppermind read-only SQLite DB with pending ticket & high observation.
	cmPath := filepath.Join(tmp, "coppermind.db")
	cmDB, err := sql.Open("sqlite", cmPath)
	if err != nil {
		t.Fatalf("open cm db: %v", err)
	}
	_, err = cmDB.Exec(`
		CREATE TABLE pending_lens_tickets (
			id TEXT PRIMARY KEY, lens_name TEXT, commit_sha TEXT, memory_id TEXT,
			repo_name TEXT, branch_name TEXT, summary TEXT, status TEXT, created_at INTEGER
		);
		CREATE TABLE memory_nodes (
			id TEXT PRIMARY KEY, derived INTEGER, status TEXT, severity TEXT
		);
		INSERT INTO pending_lens_tickets VALUES ('tkt_abc123', 'red-team', '5b4c67c', 'mem_1', 'fabrial', 'feat/fabrial-top', 'Audit TUI socket check', 'pending', 1795700000);
		INSERT INTO memory_nodes VALUES ('obs_1', 1, 'open', 'high');
		INSERT INTO memory_nodes VALUES ('obs_2', 1, 'open', 'critical');
		INSERT INTO memory_nodes VALUES ('obs_3', 1, 'resolved', 'high');
	`)
	_ = cmDB.Close()
	if err != nil {
		t.Fatalf("seed cm db: %v", err)
	}

	// 3. Oathgate read-only SQLite ledger.
	ogPath := filepath.Join(tmp, "ledger.db")
	ogDB, err := sql.Open("sqlite", ogPath)
	if err != nil {
		t.Fatalf("open og db: %v", err)
	}
	_, err = ogDB.Exec(`
		CREATE TABLE snapshots (
			id TEXT PRIMARY KEY, parent_id TEXT, repo_root TEXT, worktree_id TEXT,
			label TEXT, trigger TEXT, git_head TEXT, git_branch TEXT, cow_backend TEXT,
			duration_ms INTEGER, entries_cloned INTEGER, bytes_logical INTEGER,
			pinned INTEGER, tinmind_trace_id TEXT, created_at TEXT
		);
		INSERT INTO snapshots VALUES ('og_snap_1', '', '/tmp/fabrial', 'wt_main', 'pre-refactor', 'manual', '5b4c67c', 'main', 'apfs-clonefile', 6, 42, 16384, 1, 'tm-01', '2026-11-27T15:00:00Z');
	`)
	_ = ogDB.Close()
	if err != nil {
		t.Fatalf("seed og db: %v", err)
	}

	// 4. Tinmind zstd trace + Flightdeck jsonl trace.
	tmDir := filepath.Join(tmp, "tinmind-traces")
	fdDir := filepath.Join(tmp, "flightdeck-traces")
	_ = os.MkdirAll(tmDir, 0700)
	_ = os.MkdirAll(fdDir, 0700)

	var zBuf bytes.Buffer
	zw, err := zstd.NewWriter(&zBuf)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	_, _ = zw.Write([]byte(`{"ts":"2026-11-27T15:00:00Z","type":"cmd_exit","command":"go test ./...","exit_code":1}` + "\n"))
	_ = zw.Close()
	if err := os.WriteFile(filepath.Join(tmDir, "tm-01.jsonl.zst"), zBuf.Bytes(), 0600); err != nil {
		t.Fatalf("write zstd trace: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fdDir, "fd-01.jsonl"), []byte(`{"ts":"2026-11-27T14:00:00Z","type":"finding","data":"blocked"}`+"\n"), 0600); err != nil {
		t.Fatalf("write jsonl trace: %v", err)
	}

	col := NewCollector(CollectorConfig{
		Workdir:         tmp,
		LocksmithSock:   lockSock,
		CoppermindDBs:   []string{cmPath},
		TinmindDir:      tmDir,
		FlightdeckDir:   fdDir,
		OathgateDB:      ogPath,
		ProviderTimeout: 500 * time.Millisecond,
		SkipDoctor:      true,
	})
	snap := col.Collect(context.Background())

	if len(snap.Inbox) != 1 || snap.Inbox[0].ID != "tkt_abc123" {
		t.Fatalf("expected 1 coppermind ticket, got %+v", snap.Inbox)
	}
	if snap.OpenHighObs != 2 {
		t.Fatalf("expected 2 open high/critical observations, got %d", snap.OpenHighObs)
	}
	if len(snap.Checkpoints) != 1 || snap.Checkpoints[0].ID != "og_snap_1" || !snap.Checkpoints[0].Pinned {
		t.Fatalf("expected 1 pinned oathgate checkpoint, got %+v", snap.Checkpoints)
	}
	if len(snap.Traces) != 2 {
		t.Fatalf("expected 2 traces across tinmind + flightdeck, got %+v", snap.Traces)
	}
	if runtime.GOOS != "windows" {
		if len(snap.Leases) != 1 || snap.Leases[0].SecretName != "GITHUB_TOKEN" {
			t.Fatalf("expected 1 locksmith lease metadata item, got %+v", snap.Leases)
		}
	}
}

func TestModelNavigationAndGracefulDegradation(t *testing.T) {
	col := NewCollector(CollectorConfig{
		Workdir:         t.TempDir(),
		ProviderTimeout: 200 * time.Millisecond,
		SkipDoctor:      true,
	})
	m := NewModel(col, NewLocalActionRunner("", ""), 2*time.Second)

	snap := col.Collect(context.Background())
	_, _ = m.Update(snapshotMsg(snap))

	for pane := 0; pane < paneCount; pane++ {
		view := m.View()
		if !strings.Contains(view, "fabrial-top") {
			t.Fatalf("pane %d missing header", pane)
		}
		_, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	}

	// Pause & why toggle.
	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
	if !m.paused {
		t.Fatalf("expected Space to pause polling")
	}
	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	if !strings.Contains(m.View(), "Why fabrial-top?") {
		t.Fatalf("expected '?' to toggle --why drawer")
	}
}
