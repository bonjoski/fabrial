package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bonjoski/fabrial/pkg/ux"
)

func TestFabrialCLI_CheckFlagsAndFailClosed(t *testing.T) {
	// 1. Help text renders cleanly
	var out, errBuf bytes.Buffer
	code := runCheck([]string{"--help"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runCheck --help exited %d, stderr: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "--ai-target") || !strings.Contains(out.String(), "--diff") {
		t.Fatalf("unexpected check help output:\n%s", out.String())
	}

	// 2. Non-loopback --ai-target fails closed with UB-CLI-v2 FixForwardError JSON
	out.Reset()
	errBuf.Reset()
	code = runCheck([]string{"--diff", "--dir", t.TempDir(), "--ai-target", "https://api.openai.com", "--json"}, &out, &errBuf)
	if code == 0 {
		t.Fatal("expected non-zero exit for non-loopback --ai-target")
	}
	if strings.ContainsRune(errBuf.String(), 0x1b) {
		t.Fatalf("stderr contains raw ANSI escape: %q", errBuf.String())
	}
	var ffe ux.FixForwardError
	if err := json.Unmarshal(errBuf.Bytes(), &ffe); err != nil {
		t.Fatalf("expected FixForwardError JSON on stderr, got: %v (raw: %q)", err, errBuf.String())
	}
	if ffe.Code != "FABRIAL_CHECK_INVALID_AI_TARGET" || ffe.RemediationCmd == "" || ffe.WhyOneLiner == "" {
		t.Fatalf("unexpected FixForwardError fields: %+v", ffe)
	}

	// 3. Unknown flag fails closed with UB-CLI-v2 FixForwardError JSON
	out.Reset()
	errBuf.Reset()
	code = runCheck([]string{"--bogus-flag", "--json"}, &out, &errBuf)
	if code == 0 {
		t.Fatal("expected non-zero exit for unknown flag")
	}
	if err := json.Unmarshal(errBuf.Bytes(), &ffe); err != nil {
		t.Fatalf("expected FixForwardError JSON for unknown flag, got: %v (raw: %q)", err, errBuf.String())
	}
	if ffe.Code != "FABRIAL_CHECK_UNKNOWN_FLAG" {
		t.Fatalf("unexpected error code: %+v", ffe)
	}

	// 4. fabrial explain check works cleanly
	out.Reset()
	errBuf.Reset()
	code = runExplain([]string{"check"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runExplain check failed: %d %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "Deep Dive (--why):") || !strings.Contains(out.String(), "RFC-2026-11-22-48") {
		t.Fatalf("unexpected explain check output:\n%s", out.String())
	}
}
