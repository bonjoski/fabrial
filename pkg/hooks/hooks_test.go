package hooks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/fabrial/pkg/receipt"
)

func TestReadAndParseInput_AllDialects(t *testing.T) {
	tests := []struct {
		name     string
		client   ClientDialect
		event    HookEvent
		payload  string
		wantTool string
		wantCmd  string
		wantFile string
		wantCWD  string
		wantSess string
	}{
		{
			name:     "claude snake_case pre-tool",
			client:   ClientClaude,
			event:    EventPreTool,
			payload:  `{"hook_event_name":"PreToolUse","session_id":"sess_abc123","cwd":"/tmp/repo","tool_name":"Bash","tool_input":{"command":"go test ./..."}}`,
			wantTool: "Bash",
			wantCmd:  "go test ./...",
			wantCWD:  "/tmp/repo",
			wantSess: "sess_abc123",
		},
		{
			name:     "claude camelCase post-tool",
			client:   ClientClaude,
			event:    EventPostTool,
			payload:  `{"hookEventName":"PostToolUse","sessionId":"sess_xyz999","workingDirectory":"/tmp/repo","toolName":"Write","toolInput":{"filePath":"pkg/app.go"}}`,
			wantTool: "Write",
			wantFile: "pkg/app.go",
			wantCWD:  "/tmp/repo",
			wantSess: "sess_xyz999",
		},
		{
			name:     "cursor beforeShellExecution",
			client:   ClientCursor,
			event:    EventPreTool,
			payload:  `{"command":"git status","cwd":"/tmp/work","conversation_id":"conv_1"}`,
			wantTool: "shell",
			wantCmd:  "git status",
			wantCWD:  "/tmp/work",
			wantSess: "conv_1",
		},
		{
			name:     "cursor afterFileEdit",
			client:   ClientCursor,
			event:    EventPostTool,
			payload:  `{"file_path":"src/index.ts","workspace_roots":["/tmp/work"]}`,
			wantTool: "edit",
			wantFile: "src/index.ts",
			wantCWD:  "/tmp/work",
		},
		{
			name:     "gemini BeforeTool",
			client:   ClientGemini,
			event:    EventPreTool,
			payload:  `{"tool_name":"run_shell_command","tool_input":{"command":"npm test"}}`,
			wantTool: "run_shell_command",
			wantCmd:  "npm test",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in, err := ReadAndParseInput(strings.NewReader(tc.payload), tc.client, tc.event, DefaultMaxInputBytes, DefaultReadTimeout)
			if err != nil {
				t.Fatalf("ReadAndParseInput failed: %v", err)
			}
			if in.ToolName != tc.wantTool {
				t.Errorf("ToolName = %q, want %q", in.ToolName, tc.wantTool)
			}
			if in.Command != tc.wantCmd {
				t.Errorf("Command = %q, want %q", in.Command, tc.wantCmd)
			}
			if in.FilePath != tc.wantFile {
				t.Errorf("FilePath = %q, want %q", in.FilePath, tc.wantFile)
			}
			if in.CWD != tc.wantCWD {
				t.Errorf("CWD = %q, want %q", in.CWD, tc.wantCWD)
			}
			if tc.wantSess != "" && in.SessionID != tc.wantSess {
				t.Errorf("SessionID = %q, want %q", in.SessionID, tc.wantSess)
			}
		})
	}
}

func TestDefaultEvaluator_AllowsBenignCommands(t *testing.T) {
	eval := &DefaultEvaluator{
		ArgusSocketPath: filepath.Join(t.TempDir(), "missing-argus.sock"),
	}
	benign := []string{
		"go test -race ./...",
		"git status",
		"git push origin feat/my-branch",
		"ls -la pkg/hooks",
		"npm test",
		"pip list",
		"rm -rf ./dist",
		"chmod 600 ./tmp.txt",
		"curl -s https://example.com/healthz",
		"pip install requests",
		"npm install openai",
		"cargo add serde",
	}

	for _, cmd := range benign {
		dec, err := eval.Evaluate(context.Background(), &NormalizedHookInput{
			Client:   ClientClaude,
			Event:    EventPreTool,
			ToolName: "Bash",
			Command:  cmd,
		})
		if err != nil {
			t.Fatalf("Evaluate(%q) returned error: %v", cmd, err)
		}
		if !dec.Allow {
			t.Errorf("Evaluate(%q) denied benign command: code=%s summary=%s", cmd, dec.Code, dec.Summary)
		}
	}
}

func TestDefaultEvaluator_ArgusSocketAndStrictMode(t *testing.T) {
	// 1. Live mock Argus socket denies a package
	sockDir, err := os.MkdirTemp("/tmp", "fh-argus-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "argus.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = ln.Close() }()
	if err := os.Chmod(sockPath, 0600); err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				r := bufio.NewReader(c)
				line, err := r.ReadBytes('\n')
				if err != nil {
					return
				}
				var req argusVetRequest
				if json.Unmarshal(line, &req) != nil {
					return
				}
				resp := argusVetResponse{Verdict: "allow"}
				for _, p := range req.Packages {
					if p == "evil-quarry-pkg" {
						resp = argusVetResponse{Verdict: "deny", Reason: "quarry slopsquat heuristic hit"}
					}
				}
				b, _ := json.Marshal(resp)
				_, _ = c.Write(append(b, '\n'))
			}(conn)
		}
	}()

	eval := &DefaultEvaluator{
		ArgusSocketPath:  sockPath,
		ArgusDialTimeout: 200 * time.Millisecond,
	}

	dec, err := eval.Evaluate(context.Background(), &NormalizedHookInput{
		Client:   ClientClaude,
		Event:    EventPreTool,
		ToolName: "Bash",
		Command:  "npm install evil-quarry-pkg",
	})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if dec.Allow || dec.Code != "FABRIAL_HOOK_ARGUS_DENIED" {
		t.Fatalf("expected Argus socket deny, got %+v", dec)
	}

	// 2. Strict mode fails closed when Argus socket is offline
	strictEval := &DefaultEvaluator{
		ArgusSocketPath: filepath.Join(sockDir, "offline.sock"),
		Strict:          true,
	}
	decStrict, err := strictEval.Evaluate(context.Background(), &NormalizedHookInput{
		Client:   ClientGemini,
		Event:    EventPreTool,
		ToolName: "run_shell_command",
		Command:  "pip install requests",
	})
	if err != nil {
		t.Fatalf("Evaluate strict error: %v", err)
	}
	if decStrict.Allow || decStrict.Code != "FABRIAL_HOOK_ARGUS_OFFLINE_STRICT" {
		t.Fatalf("expected strict offline deny, got %+v", decStrict)
	}
}

func TestDefaultEvaluator_EmitsAtomicBLPRReceiptOnDeny(t *testing.T) {
	worktree := t.TempDir()
	sessionID := "sess_hooktest001"
	receiptDir := filepath.Join(worktree, ".fabrial", "receipts", sessionID)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Start a local mock Locksmith UDS signer to verify amortized UDS signing (0 Touch ID)
	sockDir, err := os.MkdirTemp("/tmp", "fh-ls-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	lsSock := filepath.Join(sockDir, "locksmith.sock")
	ln, err := net.Listen("unix", lsSock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if err := os.Chmod(lsSock, 0600); err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				r := bufio.NewReader(c)
				line, err := r.ReadBytes('\n')
				if err != nil {
					return
				}
				var req struct {
					Action    string `json:"action"`
					SessionID string `json:"session_id"`
					PAEB64    string `json:"pae_b64"`
				}
				if json.Unmarshal(line, &req) != nil {
					return
				}
				pae, _ := base64.StdEncoding.DecodeString(req.PAEB64)
				sig := ed25519.Sign(priv, pae)
				resp := map[string]string{
					"status":  "GRANTED",
					"keyid":   receipt.SessionKeyID(req.SessionID),
					"sig_b64": base64.StdEncoding.EncodeToString(sig),
				}
				b, _ := json.Marshal(resp)
				_, _ = c.Write(append(b, '\n'))
			}(conn)
		}
	}()

	eval := &DefaultEvaluator{
		WorktreeRoot:        worktree,
		ReceiptDir:          receiptDir,
		LocksmithSocketPath: lsSock,
		ArgusSocketPath:     filepath.Join(sockDir, "missing-argus.sock"),
	}

	dec, err := eval.Evaluate(context.Background(), &NormalizedHookInput{
		Client:    ClientClaude,
		Event:     EventPreTool,
		ToolName:  "Bash",
		Command:   "rm -rf /",
		SessionID: sessionID,
		CWD:       worktree,
	})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if dec.Allow {
		t.Fatal("expected rm -rf / to be denied")
	}
	if !receipt.ValidateReceiptID(dec.ReceiptID) {
		t.Fatalf("expected valid BLPR-v1 receipt_id, got %q", dec.ReceiptID)
	}

	store, err := receipt.NewStore(worktree)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := store.VerifySession(sessionID, pub)
	if err != nil {
		t.Fatalf("VerifySession failed: %v", err)
	}
	if len(verified) != 1 {
		t.Fatalf("expected 1 verified receipt, got %d", len(verified))
	}
	if verified[0].Verdict != receipt.VerdictDeny || verified[0].ReceiptID != dec.ReceiptID {
		t.Fatalf("unexpected verified receipt: %+v", verified[0])
	}
}

func TestDefaultEvaluator_PostToolQueuesAndValidatesPaths(t *testing.T) {
	worktree := t.TempDir()
	srcDir := filepath.Join(worktree, "pkg")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	targetFile := filepath.Join(srcDir, "main.go")
	if err := os.WriteFile(targetFile, []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Mock Coppermind UDS socket
	sockDir, err := os.MkdirTemp("/tmp", "fh-cm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	cmSock := filepath.Join(sockDir, "coppermind.sock")
	ln, err := net.Listen("unix", cmSock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if err := os.Chmod(cmSock, 0600); err != nil {
		t.Fatal(err)
	}

	gotSocketMsg := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		b, _ := bufio.NewReader(conn).ReadString('\n')
		gotSocketMsg <- b
	}()

	eval := &DefaultEvaluator{
		WorktreeRoot:         worktree,
		CoppermindSocketPath: cmSock,
	}

	// Valid file inside worktree
	dec, err := eval.Evaluate(context.Background(), &NormalizedHookInput{
		Client:    ClientCursor,
		Event:     EventPostTool,
		ToolName:  "edit",
		FilePath:  targetFile,
		SessionID: "sess_post1",
		CWD:       worktree,
	})
	if err != nil || !dec.Allow || dec.Code != "FABRIAL_HOOK_POST_QUEUED" {
		t.Fatalf("unexpected post-tool decision: %+v err=%v", dec, err)
	}

	pendingPath := filepath.Join(worktree, ".fabrial", "pending-index.jsonl")
	raw, err := os.ReadFile(pendingPath)
	if err != nil {
		t.Fatalf("read pending-index.jsonl: %v", err)
	}
	var rec pendingIndexRecord
	if err := json.Unmarshal(bytes.TrimSpace(raw), &rec); err != nil {
		t.Fatalf("invalid pending-index JSONL: %v (raw: %s)", err, string(raw))
	}
	if rec.RelPath != "pkg/main.go" || rec.Client != "cursor" {
		t.Fatalf("unexpected pending-index record: %+v", rec)
	}

	select {
	case msg := <-gotSocketMsg:
		if !strings.Contains(msg, "pkg/main.go") {
			t.Fatalf("unexpected coppermind socket payload: %s", msg)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("expected non-blocking notification on coppermind.sock")
	}

	// Path traversal & symlink must NOT be queued
	outsideFile := filepath.Join(t.TempDir(), "outside.txt")
	_ = os.WriteFile(outsideFile, []byte("secret"), 0600)
	symPath := filepath.Join(worktree, "escape.txt")
	if err := os.Symlink(outsideFile, symPath); err != nil {
		t.Fatal(err)
	}

	for _, badPath := range []string{"../etc/passwd", outsideFile, symPath} {
		d, err := eval.Evaluate(context.Background(), &NormalizedHookInput{
			Client:   ClientClaude,
			Event:    EventPostTool,
			FilePath: badPath,
			CWD:      worktree,
		})
		if err != nil || !d.Allow || d.Code != "FABRIAL_HOOK_POST_UNSAFE_PATH" {
			t.Fatalf("expected unsafe post-tool path %q skipped cleanly, got %+v err=%v", badPath, d, err)
		}
	}
}

func TestRenderClientResponse_AllDialects(t *testing.T) {
	deny := &Decision{
		Allow:          false,
		Code:           "FABRIAL_HOOK_DESTRUCTIVE_RM",
		Summary:        "Blocked destructive rm",
		RemediationCmd: "git status",
		Why:            "Protects host filesystem.",
	}

	// Claude
	var buf bytes.Buffer
	code, err := RenderClientResponse(&buf, ClientClaude, EventPreTool, deny)
	if err != nil || code != 0 {
		t.Fatalf("claude render failed: code=%d err=%v", code, err)
	}
	var claudeOut claudeHookOutput
	if err := json.Unmarshal(buf.Bytes(), &claudeOut); err != nil {
		t.Fatalf("invalid claude JSON: %v (%s)", err, buf.String())
	}
	if claudeOut.HookSpecificOutput.HookEventName != "PreToolUse" ||
		claudeOut.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("unexpected claude output: %+v", claudeOut)
	}

	// Cursor
	buf.Reset()
	code, err = RenderClientResponse(&buf, ClientCursor, EventPreTool, deny)
	if err != nil || code != 0 {
		t.Fatalf("cursor render failed: code=%d err=%v", code, err)
	}
	var cursorOut cursorHookOutput
	if err := json.Unmarshal(buf.Bytes(), &cursorOut); err != nil {
		t.Fatalf("invalid cursor JSON: %v (%s)", err, buf.String())
	}
	if cursorOut.Permission != "deny" || cursorOut.UserMessage == "" || cursorOut.AgentMessage == "" {
		t.Fatalf("unexpected cursor output: %+v", cursorOut)
	}

	// Gemini
	buf.Reset()
	code, err = RenderClientResponse(&buf, ClientGemini, EventPreTool, deny)
	if err != nil || code != 0 {
		t.Fatalf("gemini render failed: code=%d err=%v", code, err)
	}
	var geminiOut geminiHookOutput
	if err := json.Unmarshal(buf.Bytes(), &geminiOut); err != nil {
		t.Fatalf("invalid gemini JSON: %v (%s)", err, buf.String())
	}
	if geminiOut.Decision != "deny" || !strings.Contains(geminiOut.Reason, "Blocked destructive rm") {
		t.Fatalf("unexpected gemini output: %+v", geminiOut)
	}

	// HardBlock exit code 2 while still emitting strict valid JSON
	buf.Reset()
	hardDeny := *deny
	hardDeny.HardBlock = true
	code, err = RenderClientResponse(&buf, ClientClaude, EventPreTool, &hardDeny)
	if err != nil || code != 2 {
		t.Fatalf("expected exit code 2 for HardBlock, got code=%d err=%v", code, err)
	}
	if err := json.Unmarshal(buf.Bytes(), &claudeOut); err != nil {
		t.Fatalf("HardBlock stdout was not valid JSON: %v", err)
	}
}

func TestNormalizeHookTargetsAndRender(t *testing.T) {
	targets, err := NormalizeHookTargets([]string{"claude-code,gemini-cli"})
	if err != nil {
		t.Fatalf("NormalizeHookTargets failed: %v", err)
	}
	if len(targets) != 2 || targets[0] != ClientClaude || targets[1] != ClientGemini {
		t.Fatalf("unexpected normalized targets: %v", targets)
	}

	if _, err := NormalizeHookTargets([]string{"bogus"}); err == nil {
		t.Fatal("expected error for unknown hook target")
	}

	dir := t.TempDir()
	report, err := PlanAndApplyHooks(HooksInitOptions{
		WorktreeDir: dir,
		Apply:       false,
		Targets:     []string{"all"},
	})
	if err != nil {
		t.Fatalf("PlanAndApplyHooks dry-run failed: %v", err)
	}
	if len(report.Plans) != 3 {
		t.Fatalf("expected 3 hook plans, got %d", len(report.Plans))
	}
	// Verify 0 bytes written in dry-run
	for _, p := range report.Plans {
		if _, err := os.Stat(p.ConfigPath); !os.IsNotExist(err) {
			t.Fatalf("dry-run unexpectedly created %s", p.ConfigPath)
		}
	}

	// Verify UB-CLI-v2 <=3-line default summary
	var out bytes.Buffer
	if err := report.Render(&out, false, false); err != nil {
		t.Fatalf("Render default failed: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) > 3 {
		t.Fatalf("expected <=3 lines for default hooks dry-run render, got %d:\n%s", len(lines), out.String())
	}

	// Verify --why output
	out.Reset()
	if err := report.Render(&out, false, true); err != nil {
		t.Fatalf("Render --why failed: %v", err)
	}
	if !strings.Contains(out.String(), "Deep Dive (--why):") || !strings.Contains(out.String(), "fabrial hook eval --client gemini") {
		t.Fatalf("unexpected --why output:\n%s", out.String())
	}
}
