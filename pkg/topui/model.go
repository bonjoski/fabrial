package topui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/bonjoski/fabrial/pkg/version"
)

const (
	paneWorktrees = 0
	paneInbox     = 1
	paneTraces    = 2
	paneHealth    = 3
	paneCount     = 4
)

type confirmKind int

const (
	confirmNone confirmKind = iota
	confirmKillSession
	confirmRewindCheckpoint
)

type confirmRequest struct {
	kind      confirmKind
	session   AgentSessionStatus
	snap      CheckpointSummary
	prompt    string
}

type tickMsg time.Time
type snapshotMsg WorkstationSnapshot
type actionDoneMsg struct {
	status string
	err    error
}

// Model implements the Bubble Tea 4-pane local mission control TUI.
type Model struct {
	collector    *Collector
	actions      *LocalActionRunner
	pollInterval time.Duration

	snap       WorkstationSnapshot
	hasSnap    bool
	polling    bool
	paused     bool
	activePane int
	cursors    [paneCount]int
	subFocus   int // Pane 2 sub-toggle: 0=Traces, 1=Checkpoints

	width   int
	height  int
	showWhy bool
	confirm confirmRequest
	banner  string
}

// NewModel initializes the interactive Bubble Tea mission control model.
func NewModel(collector *Collector, actions *LocalActionRunner, pollInterval time.Duration) *Model {
	if pollInterval < 500*time.Millisecond {
		pollInterval = 2 * time.Second
	}
	return &Model{
		collector:    collector,
		actions:      actions,
		pollInterval: pollInterval,
		width:        100,
		height:       32,
	}
}

func (m *Model) Init() tea.Cmd {
	m.polling = true
	return tea.Batch(m.pollCmd(), m.tickCmd())
}

func (m *Model) tickCmd() tea.Cmd {
	return tea.Tick(m.pollInterval, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m *Model) pollCmd() tea.Cmd {
	col := m.collector
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return snapshotMsg(col.Collect(ctx))
	}
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		if m.paused || m.polling {
			return m, m.tickCmd()
		}
		m.polling = true
		return m, tea.Batch(m.pollCmd(), m.tickCmd())

	case snapshotMsg:
		m.snap = WorkstationSnapshot(msg)
		m.hasSnap = true
		m.polling = false
		m.clampCursors()
		return m, nil

	case actionDoneMsg:
		if msg.err != nil {
			m.banner = CleanText("Action error: " + msg.err.Error())
		} else {
			m.banner = CleanText(msg.status)
		}
		m.polling = true
		return m, m.pollCmd()

	case clipboardDoneMsg:
		if msg.copied {
			m.banner = CleanText("Copied triage command: " + msg.cmd)
		}
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	k := msg.String()

	// Confirmation modal intercepts all keys except y/Y and cancellation.
	if m.confirm.kind != confirmNone {
		switch k {
		case "y", "Y":
			req := m.confirm
			m.confirm = confirmRequest{}
			return m.executeConfirmed(req)
		case "n", "N", "esc", "q":
			m.confirm = confirmRequest{}
			m.banner = "Action cancelled."
			return m, nil
		case "ctrl+c":
			return m, tea.Quit
		default:
			return m, nil
		}
	}

	switch k {
	case "q", "ctrl+c":
		return m, tea.Quit

	case "tab":
		m.activePane = (m.activePane + 1) % paneCount
		return m, nil

	case "shift+tab":
		m.activePane = (m.activePane + paneCount - 1) % paneCount
		return m, nil

	case "1":
		m.activePane = paneWorktrees
		return m, nil
	case "2":
		m.activePane = paneInbox
		return m, nil
	case "3":
		m.activePane = paneTraces
		return m, nil
	case "4":
		m.activePane = paneHealth
		return m, nil

	case " ":
		m.paused = !m.paused
		if m.paused {
			m.banner = "Polling paused (press Space to resume)."
		} else {
			m.banner = "Polling resumed."
			if !m.polling {
				m.polling = true
				return m, m.pollCmd()
			}
		}
		return m, nil

	case "R":
		m.banner = "Refreshing workstation state..."
		m.polling = true
		return m, m.pollCmd()

	case "?", "h":
		m.showWhy = !m.showWhy
		return m, nil

	case "up", "p":
		if m.cursors[m.activePane] > 0 {
			m.cursors[m.activePane]--
		}
		return m, nil

	case "down", "n":
		maxIdx := m.activeListLen() - 1
		if maxIdx >= 0 && m.cursors[m.activePane] < maxIdx {
			m.cursors[m.activePane]++
		}
		return m, nil

	case "t":
		if m.activePane == paneTraces {
			m.subFocus = (m.subFocus + 1) % 2
			m.cursors[paneTraces] = 0
		}
		return m, nil

	case "k":
		return m.requestStopSession()

	case "l":
		return m.handleLensTriage()

	case "r":
		return m.handleReplay()

	case "w":
		return m.handleOathgate(true)

	case "W":
		return m.handleOathgate(false)

	case "f":
		return m.handleDoctorFix()
	}

	return m, nil
}

func (m *Model) activeListLen() int {
	switch m.activePane {
	case paneWorktrees:
		return len(m.snap.Sessions)
	case paneInbox:
		return len(m.snap.Inbox)
	case paneTraces:
		if m.subFocus == 0 {
			return len(m.snap.Traces)
		}
		return len(m.snap.Checkpoints)
	case paneHealth:
		return len(m.snap.Health)
	default:
		return 0
	}
}

func (m *Model) clampCursors() {
	for i := 0; i < paneCount; i++ {
		orig := m.activePane
		m.activePane = i
		n := m.activeListLen()
		m.activePane = orig
		if n == 0 {
			m.cursors[i] = 0
		} else if m.cursors[i] >= n {
			m.cursors[i] = n - 1
		}
	}
}

func (m *Model) requestStopSession() (tea.Model, tea.Cmd) {
	if len(m.snap.Sessions) == 0 {
		m.banner = "No active Fabrial session selected to terminate."
		return m, nil
	}
	idx := m.cursors[paneWorktrees]
	if idx < 0 || idx >= len(m.snap.Sessions) {
		idx = 0
	}
	sel := m.snap.Sessions[idx]
	m.confirm = confirmRequest{
		kind:    confirmKillSession,
		session: sel,
		prompt: fmt.Sprintf(
			"Terminate ONLY session %s (pid=%d, start=%d)? Peer sessions remain untouched. [y/N]",
			sel.SessionID, sel.PID, sel.StartTimeNs,
		),
	}
	return m, nil
}

type clipboardDoneMsg struct {
	cmd    string
	copied bool
}

func (m *Model) handleLensTriage() (tea.Model, tea.Cmd) {
	if len(m.snap.Inbox) == 0 {
		m.banner = "Coppermind lens inbox is clear (0 pending tickets)."
		return m, nil
	}
	idx := m.cursors[paneInbox]
	if idx < 0 || idx >= len(m.snap.Inbox) {
		idx = 0
	}
	cmdStr := FormatLensTriageCmd(m.snap.Inbox[idx])
	m.banner = "Triage command: " + cmdStr
	return m, func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		return clipboardDoneMsg{cmd: cmdStr, copied: copyToClipboardBestEffort(ctx, cmdStr)}
	}
}

func (m *Model) handleReplay() (tea.Model, tea.Cmd) {
	if len(m.snap.Traces) == 0 {
		m.banner = "No local Tinmind/Flightdeck traces available to replay."
		return m, nil
	}
	idx := 0
	if m.activePane == paneTraces && m.subFocus == 0 && m.cursors[paneTraces] < len(m.snap.Traces) {
		idx = m.cursors[paneTraces]
	}
	trace := m.snap.Traces[idx]
	cmd, err := m.actions.BuildReplayCmd(trace.TraceID)
	if err != nil {
		m.banner = CleanText(err.Error())
		return m, nil
	}
	return m, tea.ExecProcess(cmd, func(execErr error) tea.Msg {
		if execErr != nil {
			return actionDoneMsg{err: execErr}
		}
		return actionDoneMsg{status: "Returned from replay of " + trace.TraceID}
	})
}

func (m *Model) handleOathgate(diffOnly bool) (tea.Model, tea.Cmd) {
	if len(m.snap.Checkpoints) == 0 {
		m.banner = "No Oathgate checkpoints available."
		return m, nil
	}
	idx := 0
	if m.activePane == paneTraces && m.subFocus == 1 && m.cursors[paneTraces] < len(m.snap.Checkpoints) {
		idx = m.cursors[paneTraces]
	}
	cp := m.snap.Checkpoints[idx]
	if !diffOnly {
		m.confirm = confirmRequest{
			kind: confirmRewindCheckpoint,
			snap: cp,
			prompt: fmt.Sprintf(
				"Rewind worktree %s to Oathgate checkpoint %s (%s)? [y/N]",
				cp.RepoRoot, cp.ID, cp.Label,
			),
		}
		return m, nil
	}
	cmd, err := m.actions.BuildRewindCmd(cp.RepoRoot, cp.ID, true)
	if err != nil {
		m.banner = CleanText(err.Error())
		return m, nil
	}
	return m, tea.ExecProcess(cmd, func(execErr error) tea.Msg {
		if execErr != nil {
			return actionDoneMsg{err: execErr}
		}
		return actionDoneMsg{status: "Inspected Oathgate diff for " + cp.ID}
	})
}

func (m *Model) handleDoctorFix() (tea.Model, tea.Cmd) {
	pillar := ""
	if m.activePane == paneHealth && len(m.snap.Health) > 0 && m.cursors[paneHealth] < len(m.snap.Health) {
		sel := m.snap.Health[m.cursors[paneHealth]]
		if sel.Status != "READY" && sel.Status != "ONLINE" {
			pillar = strings.ToLower(sel.Pillar)
		}
	}
	cmd, err := m.actions.BuildDoctorFixCmd(pillar)
	if err != nil {
		m.banner = CleanText(err.Error())
		return m, nil
	}
	return m, tea.ExecProcess(cmd, func(execErr error) tea.Msg {
		if execErr != nil {
			return actionDoneMsg{err: execErr}
		}
		return actionDoneMsg{status: "Completed scoped fabrial doctor --fix"}
	})
}

func (m *Model) executeConfirmed(req confirmRequest) (tea.Model, tea.Cmd) {
	switch req.kind {
	case confirmKillSession:
		actions := m.actions
		sel := req.session
		return m, func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := actions.StopSession(ctx, sel.SessionID, sel.PID, sel.StartTimeNs); err != nil {
				return actionDoneMsg{err: err}
			}
			return actionDoneMsg{status: "Terminated/revoked session " + sel.SessionID}
		}

	case confirmRewindCheckpoint:
		cmd, err := m.actions.BuildRewindCmd(req.snap.RepoRoot, req.snap.ID, false)
		if err != nil {
			m.banner = CleanText(err.Error())
			return m, nil
		}
		return m, tea.ExecProcess(cmd, func(execErr error) tea.Msg {
			if execErr != nil {
				return actionDoneMsg{err: execErr}
			}
			return actionDoneMsg{status: "Rewound checkpoint " + req.snap.ID}
		})
	}
	return m, nil
}

var (
	styleHeader = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("229")).
			Background(lipgloss.Color("57")).
			Padding(0, 1)

	styleTabActive = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("230")).
			Background(lipgloss.Color("62")).
			Padding(0, 1)

	styleTabInactive = lipgloss.NewStyle().
				Foreground(lipgloss.Color("248")).
				Padding(0, 1)

	styleSection = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("81"))

	styleDim = lipgloss.NewStyle().
			Foreground(lipgloss.Color("243"))

	styleSelected = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("229")).
			Background(lipgloss.Color("238"))

	styleOK   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))
	styleWarn = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214"))
	styleErr  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))

	styleModal = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("196")).
			Padding(1, 2).
			Bold(true)

	styleFooter = lipgloss.NewStyle().
			Foreground(lipgloss.Color("249")).
			Background(lipgloss.Color("236")).
			Padding(0, 1)
)

func (m *Model) View() string {
	var b strings.Builder

	// 1. Header bar
	stateBadge := "LIVE"
	if m.paused {
		stateBadge = "PAUSED"
	}
	headerText := fmt.Sprintf(
		"fabrial-top v%s | %s | poll %dms | worktrees:%d sessions:%d leases:%d inbox:%d high-obs:%d",
		version.Version, stateBadge, m.snap.PollMs,
		len(m.snap.Worktrees), len(m.snap.Sessions), len(m.snap.Leases),
		len(m.snap.Inbox), m.snap.OpenHighObs,
	)
	b.WriteString(styleHeader.Render(truncateLine(headerText, maxInt(40, m.width-2))))
	b.WriteByte('\n')

	// 2. Tabs
	tabs := []string{
		"[1] Worktrees & Sessions",
		fmt.Sprintf("[2] Coppermind Inbox (%d)", len(m.snap.Inbox)),
		fmt.Sprintf("[3] Traces (%d) & Checkpoints (%d)", len(m.snap.Traces), len(m.snap.Checkpoints)),
		"[4] Doctor Health",
	}
	var tabParts []string
	for i, t := range tabs {
		if i == m.activePane {
			tabParts = append(tabParts, styleTabActive.Render(t))
		} else {
			tabParts = append(tabParts, styleTabInactive.Render(t))
		}
	}
	b.WriteString(strings.Join(tabParts, " "))
	b.WriteString("\n\n")

	// 3. Active pane body (or confirmation modal)
	if m.confirm.kind != confirmNone {
		b.WriteString(styleModal.Render(m.confirm.prompt))
		b.WriteString("\n\n")
	} else if !m.hasSnap {
		b.WriteString(styleDim.Render("Collecting local workstation state (strict 500ms per-source budget, zero Touch ID)..."))
		b.WriteString("\n")
	} else {
		switch m.activePane {
		case paneWorktrees:
			b.WriteString(m.renderWorktreesAndSessions())
		case paneInbox:
			b.WriteString(m.renderInbox())
		case paneTraces:
			b.WriteString(m.renderTracesAndCheckpoints())
		case paneHealth:
			b.WriteString(m.renderHealth())
		}
	}

	if m.showWhy {
		b.WriteString("\n")
		b.WriteString(styleSection.Render("Why fabrial-top? (RFC-2026-11-25-63)"))
		b.WriteByte('\n')
		b.WriteString(styleDim.Render("• Zero-hop-tax companion binary: never imported by fabrial CLI; 0.00ms impact on fabrial hook eval.\n"))
		b.WriteString(styleDim.Render("• Read-only N=8 safe: SQLite WAL opened ?mode=ro; Locksmith queried via list_leases only (0 Touch ID prompts).\n"))
		b.WriteString(styleDim.Render("• Fail-closed security: ANSI/OSC-52/Bidi stripped, secret-redacted, Lstat+SO_PEERCRED verified, PID+StartTime checked before SIGKILL.\n"))
	}

	if m.banner != "" {
		b.WriteString("\n")
		b.WriteString(styleWarn.Render("> " + truncateLine(m.banner, maxInt(40, m.width-4))))
		b.WriteByte('\n')
	}

	// 4. Footer keybinding bar
	b.WriteString("\n")
	footer := "Tab/1-4:pane  Up/Dn:select  k:stop-session  l:lens-cmd  r:replay  w/W:diff/rewind  f:doctor-fix  Space:pause  R:refresh  ?:why  q:quit"
	b.WriteString(styleFooter.Render(truncateLine(footer, maxInt(40, m.width-2))))
	b.WriteByte('\n')
	return b.String()
}

func (m *Model) renderWorktreesAndSessions() string {
	var b strings.Builder
	b.WriteString(styleSection.Render("Git Worktrees"))
	b.WriteByte('\n')
	if len(m.snap.Worktrees) == 0 {
		b.WriteString(styleDim.Render("  (none detected — run inside a git repo or pass --dir)\n"))
	} else {
		limit := minInt(len(m.snap.Worktrees), 8)
		for i := 0; i < limit; i++ {
			wt := m.snap.Worktrees[i]
			dirtyBadge := styleOK.Render("clean")
			if wt.DirtyFiles > 0 {
				dirtyBadge = styleWarn.Render(fmt.Sprintf("%d dirty", wt.DirtyFiles))
			}
			line := fmt.Sprintf("  %-24s %-12s %s  %s", truncateLine(wt.Branch, 24), wt.HeadSHA, dirtyBadge, truncateLine(wt.Path, 48))
			b.WriteString(line + "\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(styleSection.Render("Fabrial Sessions (press k to stop selected session)"))
	b.WriteByte('\n')
	if len(m.snap.Sessions) == 0 {
		b.WriteString(styleDim.Render("  (no active ambient sessions — start one with `fabrial session begin`)\n"))
	} else {
		for i, s := range m.snap.Sessions {
			if i >= 10 {
				break
			}
			state := styleOK.Render(fmt.Sprintf("TTL %ds", s.RemainingSec))
			if s.Revoked {
				state = styleErr.Render("REVOKED")
			} else if s.RemainingSec == 0 {
				state = styleDim.Render("EXPIRED")
			}
			role := "child"
			if s.IsMaster {
				role = "master"
			}
			row := fmt.Sprintf("  %-28s %-6s %-10s scopes=%s receipts=%d",
				truncateLine(s.SessionID, 28), role, state, strings.Join(s.Scopes, ","), s.ReceiptCount)
			if i == m.cursors[paneWorktrees] {
				b.WriteString(styleSelected.Render(">" + row[1:]) + "\n")
			} else {
				b.WriteString(row + "\n")
			}
		}
	}

	b.WriteString("\n")
	b.WriteString(styleSection.Render("Locksmith Ephemeral Leases (Metadata Only — Zero Secrets / Zero Touch ID)"))
	b.WriteByte('\n')
	if len(m.snap.Leases) == 0 {
		b.WriteString(styleDim.Render("  (no active leases or locksmith daemon offline)\n"))
	} else {
		for i, l := range m.snap.Leases {
			if i >= 8 {
				break
			}
			ttl := styleOK.Render(fmt.Sprintf("%ds", l.RemainingSec))
			if l.Revoked {
				ttl = styleErr.Render("REVOKED")
			} else if l.RemainingSec < 30 {
				ttl = styleWarn.Render(fmt.Sprintf("%ds", l.RemainingSec))
			}
			b.WriteString(fmt.Sprintf("  %-20s secret=%-20s pid=%-6d uses=%d/%d ttl=%s\n",
				truncateLine(l.LeaseID, 20), truncateLine(l.SecretName, 20), l.ClientPID, l.UsesCount, l.MaxUses, ttl))
		}
	}
	return b.String()
}

func (m *Model) renderInbox() string {
	var b strings.Builder
	obsStyle := styleOK
	if m.snap.OpenHighObs > 0 {
		obsStyle = styleErr
	}
	b.WriteString(styleSection.Render("Coppermind Pending Commit-Lens Inbox") + "  " +
		obsStyle.Render(fmt.Sprintf("Open High/Critical Observations: %d", m.snap.OpenHighObs)) + "\n")
	if len(m.snap.Inbox) == 0 {
		b.WriteString(styleDim.Render("  (no pending lens tickets or coppermind DB offline)\n"))
		return b.String()
	}
	for i, t := range m.snap.Inbox {
		if i >= 16 {
			break
		}
		row := fmt.Sprintf("  [%-18s] %-14s %-12s %s",
			truncateLine(t.LensName, 18), truncateLine(t.RepoName, 14), truncateLine(t.BranchName, 12), truncateLine(t.Summary, 48))
		if i == m.cursors[paneInbox] {
			b.WriteString(styleSelected.Render(">" + row[1:]) + "\n")
		} else {
			b.WriteString(row + "\n")
		}
	}
	b.WriteString(styleDim.Render("\n  Press `l` to copy/display the safe Coppermind triage command for the selected ticket.\n"))
	return b.String()
}

func (m *Model) renderTracesAndCheckpoints() string {
	var b strings.Builder
	traceTitle := "Tinmind / Flightdeck Traces (press r to replay)"
	snapTitle := "Oathgate CoW Checkpoints (press w to diff, W to rewind)"
	if m.subFocus == 0 {
		traceTitle += " [ACTIVE — press t to switch]"
	} else {
		snapTitle += " [ACTIVE — press t to switch]"
	}

	b.WriteString(styleSection.Render(traceTitle) + "\n")
	if len(m.snap.Traces) == 0 {
		b.WriteString(styleDim.Render("  (no traces found in ~/.tinmind/traces or ~/.flightdeck/traces)\n"))
	} else {
		for i, tr := range m.snap.Traces {
			if i >= 8 {
				break
			}
			failBadge := styleOK.Render("0 fails")
			if tr.FailureCount > 0 {
				failBadge = styleErr.Render(fmt.Sprintf("%d fails", tr.FailureCount))
			}
			row := fmt.Sprintf("  %-26s %-10s %4d ev  %s  %s",
				truncateLine(tr.TraceID, 26), tr.Source+"/"+tr.Format, tr.EventCount, failBadge, truncateLine(tr.LastCommand, 30))
			if m.subFocus == 0 && i == m.cursors[paneTraces] {
				b.WriteString(styleSelected.Render(">" + row[1:]) + "\n")
			} else {
				b.WriteString(row + "\n")
			}
		}
	}

	b.WriteString("\n" + styleSection.Render(snapTitle) + "\n")
	if len(m.snap.Checkpoints) == 0 {
		b.WriteString(styleDim.Render("  (no Oathgate checkpoints found in ~/.oathgate/ledger.db)\n"))
	} else {
		for i, cp := range m.snap.Checkpoints {
			if i >= 8 {
				break
			}
			row := fmt.Sprintf("  %-18s %-14s %-10s %3dms  %s",
				truncateLine(cp.ID, 18), truncateLine(cp.GitBranch, 14), cp.CowBackend, cp.DurationMs, truncateLine(cp.Label, 32))
			if m.subFocus == 1 && i == m.cursors[paneTraces] {
				b.WriteString(styleSelected.Render(">" + row[1:]) + "\n")
			} else {
				b.WriteString(row + "\n")
			}
		}
	}
	return b.String()
}

func (m *Model) renderHealth() string {
	var b strings.Builder
	b.WriteString(styleSection.Render("Fabrial Security Pillar Health (press f to run scoped fabrial doctor --fix)") + "\n")
	if len(m.snap.Health) == 0 {
		b.WriteString(styleDim.Render("  (doctor probe pending or skipped)\n"))
	} else {
		for i, h := range m.snap.Health {
			stStyle := styleDim
			switch h.Status {
			case "READY", "ONLINE":
				stStyle = styleOK
			case "DEGRADED":
				stStyle = styleWarn
			case "OFFLINE":
				stStyle = styleErr
			}
			row := fmt.Sprintf("  %-12s [%s] %3dms  %s",
				h.Pillar, stStyle.Render(fmt.Sprintf("%-8s", h.Status)), h.LatencyMs, truncateLine(h.Details, 52))
			if i == m.cursors[paneHealth] {
				b.WriteString(styleSelected.Render(">" + row[1:]) + "\n")
			} else {
				b.WriteString(row + "\n")
			}
		}
	}

	b.WriteString("\n" + styleSection.Render("Local Read-Only Provider Status (500ms Hard Timeout)") + "\n")
	for _, p := range m.snap.Providers {
		pStyle := styleOK
		switch p.State {
		case ProviderOffline:
			pStyle = styleDim
		case ProviderTimeout, ProviderBackoff:
			pStyle = styleWarn
		case ProviderError:
			pStyle = styleErr
		}
		b.WriteString(fmt.Sprintf("  %-22s [%s] %3dms  %s\n",
			p.Name, pStyle.Render(fmt.Sprintf("%-7s", string(p.State))), p.LatencyMs, truncateLine(p.Detail, 50)))
	}
	return b.String()
}

func truncateLine(s string, maxLen int) string {
	if maxLen <= 3 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen-3]) + "..."
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
