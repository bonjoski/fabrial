package topui

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	maxSanitizedStringLen = 512
)

var (
	// ANSI CSI sequences: ESC [ ... final byte 0x40-0x7E
	ansiCSIRe = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
	// ANSI OSC sequences: ESC ] ... BEL or ST (ESC \), including OSC-52 clipboard writes
	ansiOSCRe = regexp.MustCompile(`\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?`)
	// ANSI DCS / SOS / PM / APC string sequences
	ansiDCSRe = regexp.MustCompile(`\x1b[PX^_][^\x1b]*(?:\x1b\\)?`)
	// Remaining 2-byte ESC sequences (e.g., ESC c reset, ESC ( B charset)
	ansiEsc2Re = regexp.MustCompile(`\x1b[@-Z\\-_]|\x1b[()][A-Za-z0-9]`)
	// 8-bit C1 CSI / OSC sequences (single-byte 0x9B / 0x9D)
	c1CSIRe = regexp.MustCompile(`\x9b[0-?]*[ -/]*[@-~]`)
	c1OSCRe = regexp.MustCompile(`\x9d[^\x07\x9c]*(?:\x07|\x9c)?`)

	// High-confidence secret patterns redacted before anything enters WorkstationSnapshot.
	secretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`),
		regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{12,}\b`),
		regexp.MustCompile(`\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b`),
		regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),
		regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
		regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),
		regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{20,}\b`),
		regexp.MustCompile(`\b(?:rk|pk)_live_[0-9A-Za-z]{16,}\b`),
		regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b`),
		regexp.MustCompile(`(?i)\b((?:api[_-]?key|secret|token|password|passwd|auth[_-]?token|master[_-]?token)\s*[:=]\s*["']?)([A-Za-z0-9._/+=-]{8,})(["']?)`),
	}
)

// SanitizeTUIString strips all ANSI CSI/OSC/DCS/C1 escape sequences, Unicode Bidi
// overrides/isolates (U+202A-U+202E, U+2066-U+2069, U+200E, U+200F, U+061C), and
// C0/DEL control characters from untrusted workstation strings (git branches, commit
// summaries, file paths, trace commands) before rendering or JSON output.
func SanitizeTUIString(raw string) string {
	if raw == "" {
		return ""
	}
	if !utf8.ValidString(raw) {
		raw = strings.ToValidUTF8(raw, "")
	}

	s := ansiOSCRe.ReplaceAllString(raw, "")
	s = ansiDCSRe.ReplaceAllString(s, "")
	s = ansiCSIRe.ReplaceAllString(s, "")
	s = ansiEsc2Re.ReplaceAllString(s, "")
	s = c1OSCRe.ReplaceAllString(s, "")
	s = c1CSIRe.ReplaceAllString(s, "")

	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		// Strip remaining ESC / C0 / DEL / C1 controls.
		if r == '\t' || r == '\n' || r == '\r' {
			b.WriteByte(' ')
			continue
		}
		if r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F) {
			continue
		}
		// Strip Unicode Bidi overrides, embeddings, isolates, and direction marks.
		if isBidiControlRune(r) {
			continue
		}
		// Strip Unicode Tag block (U+E0000-U+E007F) used in prompt/UI cloaking.
		if r >= 0xE0000 && r <= 0xE007F {
			continue
		}
		b.WriteRune(r)
	}

	out := strings.TrimSpace(b.String())
	if len(out) > maxSanitizedStringLen {
		// Truncate safely on rune boundary.
		runes := []rune(out)
		if len(runes) > maxSanitizedStringLen {
			out = string(runes[:maxSanitizedStringLen-3]) + "..."
		}
	}
	return out
}

func isBidiControlRune(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E: // LRE, RLE, PDF, LRO, RLO
		return true
	case r >= 0x2066 && r <= 0x2069: // LRI, RLI, FSI, PDI
		return true
	case r == 0x200E || r == 0x200F || r == 0x061C: // LRM, RLM, ALM
		return true
	default:
		return false
	}
}

// RedactSecrets replaces high-confidence secret material with [REDACTED] so no
// raw credential value can ever appear in TUI frames or JSON snapshots.
func RedactSecrets(raw string) string {
	if raw == "" {
		return ""
	}
	out := raw
	for i, re := range secretPatterns {
		if i == len(secretPatterns)-1 {
			out = re.ReplaceAllString(out, "${1}[REDACTED]${3}")
		} else {
			out = re.ReplaceAllString(out, "[REDACTED]")
		}
	}
	return out
}

// CleanText applies secret redaction followed by full TUI control/Bidi sanitization.
func CleanText(raw string) string {
	return SanitizeTUIString(RedactSecrets(raw))
}

// SanitizeSnapshot recursively scrubs every string field in WorkstationSnapshot in place.
func SanitizeSnapshot(s *WorkstationSnapshot) {
	if s == nil {
		return
	}
	s.Workdir = CleanText(s.Workdir)

	for i := range s.Worktrees {
		s.Worktrees[i].Path = CleanText(s.Worktrees[i].Path)
		s.Worktrees[i].Branch = CleanText(s.Worktrees[i].Branch)
		s.Worktrees[i].HeadSHA = CleanText(s.Worktrees[i].HeadSHA)
	}

	for i := range s.Sessions {
		s.Sessions[i].SessionID = CleanText(s.Sessions[i].SessionID)
		s.Sessions[i].ParentID = CleanText(s.Sessions[i].ParentID)
		s.Sessions[i].SubtaskID = CleanText(s.Sessions[i].SubtaskID)
		s.Sessions[i].Workspace = CleanText(s.Sessions[i].Workspace)
		for j := range s.Sessions[i].Scopes {
			s.Sessions[i].Scopes[j] = CleanText(s.Sessions[i].Scopes[j])
		}
	}

	for i := range s.Leases {
		s.Leases[i].LeaseID = CleanText(s.Leases[i].LeaseID)
		s.Leases[i].SecretName = CleanText(s.Leases[i].SecretName)
		s.Leases[i].SpiffeID = CleanText(s.Leases[i].SpiffeID)
	}

	for i := range s.Inbox {
		s.Inbox[i].ID = CleanText(s.Inbox[i].ID)
		s.Inbox[i].LensName = CleanText(s.Inbox[i].LensName)
		s.Inbox[i].CommitSHA = CleanText(s.Inbox[i].CommitSHA)
		s.Inbox[i].MemoryID = CleanText(s.Inbox[i].MemoryID)
		s.Inbox[i].RepoName = CleanText(s.Inbox[i].RepoName)
		s.Inbox[i].BranchName = CleanText(s.Inbox[i].BranchName)
		s.Inbox[i].Summary = CleanText(s.Inbox[i].Summary)
		s.Inbox[i].Status = CleanText(s.Inbox[i].Status)
		s.Inbox[i].TriageCmd = CleanText(s.Inbox[i].TriageCmd)
	}

	for i := range s.Traces {
		s.Traces[i].TraceID = CleanText(s.Traces[i].TraceID)
		s.Traces[i].Source = CleanText(s.Traces[i].Source)
		s.Traces[i].Format = CleanText(s.Traces[i].Format)
		s.Traces[i].FilePath = CleanText(s.Traces[i].FilePath)
		s.Traces[i].LastCommand = CleanText(s.Traces[i].LastCommand)
		s.Traces[i].ReplayCommand = CleanText(s.Traces[i].ReplayCommand)
	}

	for i := range s.Checkpoints {
		s.Checkpoints[i].ID = CleanText(s.Checkpoints[i].ID)
		s.Checkpoints[i].ParentID = CleanText(s.Checkpoints[i].ParentID)
		s.Checkpoints[i].RepoRoot = CleanText(s.Checkpoints[i].RepoRoot)
		s.Checkpoints[i].WorktreeID = CleanText(s.Checkpoints[i].WorktreeID)
		s.Checkpoints[i].Label = CleanText(s.Checkpoints[i].Label)
		s.Checkpoints[i].Trigger = CleanText(s.Checkpoints[i].Trigger)
		s.Checkpoints[i].GitHead = CleanText(s.Checkpoints[i].GitHead)
		s.Checkpoints[i].GitBranch = CleanText(s.Checkpoints[i].GitBranch)
		s.Checkpoints[i].CowBackend = CleanText(s.Checkpoints[i].CowBackend)
		s.Checkpoints[i].TinmindTraceID = CleanText(s.Checkpoints[i].TinmindTraceID)
	}

	for i := range s.Health {
		s.Health[i].Pillar = CleanText(s.Health[i].Pillar)
		s.Health[i].Role = CleanText(s.Health[i].Role)
		s.Health[i].Status = CleanText(s.Health[i].Status)
		s.Health[i].Details = CleanText(s.Health[i].Details)
		s.Health[i].BinaryPath = CleanText(s.Health[i].BinaryPath)
		s.Health[i].SocketPath = CleanText(s.Health[i].SocketPath)
	}

	for i := range s.Providers {
		s.Providers[i].Name = CleanText(s.Providers[i].Name)
		s.Providers[i].Detail = CleanText(s.Providers[i].Detail)
		s.Providers[i].Hint = CleanText(s.Providers[i].Hint)
	}
}
