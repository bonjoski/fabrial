package integration

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bonjoski/fabrial/pkg/ux"
)

// ErrMCPTOMLInjection is returned fail-closed when a server name, command, or
// argument contains control characters, newlines, or invalid TOML syntax that
// could inject arbitrary TOML keys or tables into config.toml.
var ErrMCPTOMLInjection = errors.New("unsafe TOML value rejected to prevent config injection (fail-closed)")

const maxTOMLNestingDepth = 32

type tomlNodeKind int

const (
	tomlNodeTable tomlNodeKind = iota
	tomlNodeInlineTable
	tomlNodeArrayOfTables
	tomlNodeValue
)

type tomlNode struct {
	kind              tomlNodeKind
	definedExplicitly bool
	dottedDefined     bool
	children          map[string]*tomlNode
	arrayTables       []*tomlNode
	val               interface{}
}

func newTOMLTableNode(explicit bool) *tomlNode {
	return &tomlNode{
		kind:              tomlNodeTable,
		definedExplicitly: explicit,
		children:          make(map[string]*tomlNode),
	}
}

type tomlLineSpan struct {
	startLine int
	endLine   int
	prefix    string // "" when inside [mcp_servers], "mcp_servers." when at root
}

type tomlSection struct {
	path            []string
	isArrayTable    bool
	headerLine      int
	lastContentLine int
	endLine         int
}

type tomlMCPServerEntry struct {
	name        string
	command     string
	hasCommand  bool
	args        []string
	hasArgs     bool
	argsValid   bool
	sectionIdx  int
	kvSpan      *tomlLineSpan
	dottedSpans []tomlLineSpan
}

type parsedCodexTOML struct {
	root        *tomlNode
	lines       []string
	sections    []tomlSection
	mcpServers  map[string]*tomlMCPServerEntry
	hasMCPTable bool
}

// ValidateCodexTOML strictly parses and validates a Codex TOML document without
// modifying it, failing closed with FABRIAL_INIT_MCP_INVALID_TOML on syntax or
// structural errors (unclosed quotes/brackets, duplicate headers/keys, etc.).
func ValidateCodexTOML(data []byte) error {
	_, err := parseCodexTOML(data, "config.toml", TargetCodex)
	return err
}

func processCodexTOMLTarget(
	target string,
	baseDir string,
	relPath string,
	canonical map[string]MCPServerSpec,
	conjoinerWrapped bool,
	apply bool,
	nowFn func() time.Time,
) (*MCPTargetPlan, error) {
	fullPath := filepath.Join(baseDir, relPath)

	// Strictly reject any symlink along the relative path inside baseDir before reading or writing.
	if err := checkNoSymlinksAlongRel(baseDir, relPath); err != nil {
		return nil, err
	}

	var originalBytes []byte
	exists := false

	fi, lErr := os.Lstat(fullPath)
	if lErr == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, symlinkFixForwardError(fullPath)
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("IDE config path %s is not a regular file", fullPath)
		}
		data, rErr := os.ReadFile(fullPath)
		if rErr != nil {
			return nil, fmt.Errorf("read existing %s: %w", fullPath, rErr)
		}
		originalBytes = data
		exists = true
	} else if !os.IsNotExist(lErr) {
		return nil, fmt.Errorf("lstat %s: %w", fullPath, lErr)
	}

	outData, plan, err := MergeCodexTOML(originalBytes, canonical, fullPath, target)
	if err != nil {
		return nil, err
	}
	plan.Exists = exists
	plan.ConjoinerWrapped = conjoinerWrapped

	if !apply {
		return plan, nil
	}

	// Ensure parent directories exist safely (no symlinks)
	if err := ensureSafeParentDirs(baseDir, filepath.Dir(relPath)); err != nil {
		return nil, err
	}

	// Backup existing file to <configPath>.bak.<ts> (0600) before replacing
	if plan.Exists {
		backupPath, bErr := writeAtomicBackup(fullPath, originalBytes, nowFn())
		if bErr != nil {
			return nil, bErr
		}
		plan.BackupPath = backupPath
	}

	// Re-verify no symlink was planted before atomic replace
	if err := checkNoSymlinksAlongRel(baseDir, relPath); err != nil {
		return nil, err
	}

	// Atomic write (O_CREAT|O_EXCL, 0600) + fsync + rename
	if err := atomicWriteConfig(fullPath, outData); err != nil {
		return nil, err
	}

	plan.Applied = true
	return plan, nil
}

// MergeCodexTOML performs a surgical, comment-preserving merge of the 5 canonical
// [mcp_servers.<name>] blocks into a Codex config.toml document and verifies full
// round-trip TOML validity on the merged output before returning.
func MergeCodexTOML(existing []byte, canonical map[string]MCPServerSpec, configPath string, target string) ([]byte, *MCPTargetPlan, error) {
	if target == "" {
		target = TargetCodex
	}
	doc, err := parseCodexTOML(existing, configPath, target)
	if err != nil {
		return nil, nil, err
	}

	plan := &MCPTargetPlan{
		Target:     target,
		ConfigPath: configPath,
	}

	// Track preserved user-owned MCP servers (any key not in CanonicalMCPServerOrder)
	for existingKey := range doc.mcpServers {
		if _, isCanonical := canonical[existingKey]; !isCanonical {
			plan.UserServersPreserved = append(plan.UserServersPreserved, existingKey)
		}
	}
	sort.Strings(plan.UserServersPreserved)

	type lineEdit struct {
		startLine   int
		endLine     int
		replacement []string // nil/empty removes the lines
	}
	var edits []lineEdit
	var appendBlocks [][]string

	var diffLines []string
	diffLines = append(diffLines, fmt.Sprintf("--- %s (target: %s)", configPath, target))

	for _, name := range CanonicalMCPServerOrder {
		spec, ok := canonical[name]
		if !ok {
			continue
		}
		if err := validateTOMLKeySegment(name); err != nil {
			return nil, nil, err
		}
		blockLines, err := formatCodexMCPServerBlock(name, spec)
		if err != nil {
			return nil, nil, err
		}

		entry, exists := doc.mcpServers[name]
		if !exists {
			plan.ServersAdded = append(plan.ServersAdded, name)
			appendBlocks = append(appendBlocks, blockLines)
			diffLines = append(diffLines, fmt.Sprintf("+ mcp_servers.%s: %s %s", name, spec.Command, strings.Join(spec.Args, " ")))
			continue
		}

		if codexSpecMatches(entry, spec) {
			plan.ServersUnchanged = append(plan.ServersUnchanged, name)
			diffLines = append(diffLines, fmt.Sprintf("= mcp_servers.%s: unchanged", name))
			continue
		}

		plan.ServersUpdated = append(plan.ServersUpdated, name)
		diffLines = append(diffLines, fmt.Sprintf("~ mcp_servers.%s: %s %s", name, spec.Command, strings.Join(spec.Args, " ")))

		switch {
		case entry.sectionIdx >= 0:
			sec := doc.sections[entry.sectionIdx]
			edits = append(edits, lineEdit{
				startLine:   sec.headerLine,
				endLine:     sec.lastContentLine,
				replacement: blockLines,
			})
		case entry.kvSpan != nil:
			inlineLine, err := formatCodexMCPServerInline(entry.kvSpan.prefix+name, spec)
			if err != nil {
				return nil, nil, err
			}
			edits = append(edits, lineEdit{
				startLine:   entry.kvSpan.startLine,
				endLine:     entry.kvSpan.endLine,
				replacement: []string{inlineLine},
			})
		case len(entry.dottedSpans) > 0:
			for _, sp := range entry.dottedSpans {
				edits = append(edits, lineEdit{
					startLine:   sp.startLine,
					endLine:     sp.endLine,
					replacement: nil,
				})
			}
			appendBlocks = append(appendBlocks, blockLines)
		default:
			appendBlocks = append(appendBlocks, blockLines)
		}
	}

	if len(plan.UserServersPreserved) > 0 {
		diffLines = append(diffLines, fmt.Sprintf("  preserved user servers: %s", strings.Join(plan.UserServersPreserved, ", ")))
	}
	plan.Diff = strings.Join(diffLines, "\n")

	// Start from existing lines (or empty if brand new / whitespace-only with no comments)
	outLines := append([]string(nil), doc.lines...)
	if len(strings.TrimSpace(string(existing))) == 0 {
		outLines = nil
	}

	// Apply surgical line-range replacements from bottom to top so indices remain stable.
	if len(edits) > 0 {
		sort.Slice(edits, func(i, j int) bool {
			return edits[i].startLine > edits[j].startLine
		})
		for _, ed := range edits {
			if ed.startLine < 0 || ed.endLine >= len(outLines) || ed.startLine > ed.endLine {
				return nil, nil, fmt.Errorf("internal TOML merge range error for %s: [%d..%d] out of %d lines", configPath, ed.startLine, ed.endLine, len(outLines))
			}
			tail := append([]string(nil), outLines[ed.endLine+1:]...)
			outLines = append(outLines[:ed.startLine], ed.replacement...)
			outLines = append(outLines, tail...)
		}
	}

	// Append newly added canonical blocks cleanly with blank-line separation.
	for _, blk := range appendBlocks {
		if len(outLines) > 0 && strings.TrimSpace(outLines[len(outLines)-1]) != "" {
			outLines = append(outLines, "")
		}
		outLines = append(outLines, blk...)
	}

	var outData []byte
	if len(outLines) > 0 {
		outData = []byte(strings.Join(outLines, "\n") + "\n")
	} else {
		outData = []byte{}
	}

	// Full post-merge TOML round-trip validation BEFORE ever touching disk.
	roundTrip, rtErr := parseCodexTOML(outData, configPath, target)
	if rtErr != nil {
		return nil, nil, fmt.Errorf("post-merge TOML round-trip validation failed for %s: %w", configPath, rtErr)
	}
	for _, name := range CanonicalMCPServerOrder {
		spec, ok := canonical[name]
		if !ok {
			continue
		}
		entry, exists := roundTrip.mcpServers[name]
		if !exists || !codexSpecMatches(entry, spec) {
			return nil, nil, fmt.Errorf("post-merge TOML validation failed: canonical server %q mismatch in %s", name, configPath)
		}
	}
	for _, preserved := range plan.UserServersPreserved {
		if _, exists := roundTrip.mcpServers[preserved]; !exists {
			return nil, nil, fmt.Errorf("post-merge TOML validation failed: user server %q lost in %s", preserved, configPath)
		}
	}

	return outData, plan, nil
}

func codexSpecMatches(entry *tomlMCPServerEntry, desired MCPServerSpec) bool {
	if entry == nil || !entry.hasCommand || entry.command != desired.Command {
		return false
	}
	if !entry.hasArgs {
		return len(desired.Args) == 0
	}
	if !entry.argsValid {
		return false
	}
	return reflect.DeepEqual(entry.args, desired.Args)
}

func validateTOMLKeySegment(seg string) error {
	if seg == "" {
		return tomlInjectionError("empty TOML table key segment")
	}
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlphaNum && c != '_' && c != '-' {
			return tomlInjectionError(fmt.Sprintf("invalid TOML key segment %q", seg))
		}
	}
	return nil
}

// formatTOMLBasicString strictly formats s as a TOML basic string, rejecting any
// control characters (including newlines, carriage returns, tabs, NUL, ANSI ESC),
// bidi override characters, or invalid UTF-8 to prevent TOML injection.
func formatTOMLBasicString(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", tomlInjectionError("invalid UTF-8 in TOML string value")
	}
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		if r < 0x20 || r == 0x7f || isBidiControlRune(r) {
			return "", tomlInjectionError(fmt.Sprintf("disallowed control character U+%04X in TOML string value", r))
		}
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}

func isBidiControlRune(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F || r == 0x061C
}

func tomlInjectionError(detail string) error {
	return fmt.Errorf("%w: %w", ErrMCPTOMLInjection, &ux.FixForwardError{
		Tool:           "fabrial",
		Code:           "FABRIAL_INIT_MCP_TOML_INJECTION",
		Summary:        "Refused unsafe TOML value in Codex config generation",
		RemediationCmd: "fabrial init --mcp --target codex",
		WhyOneLiner:    "Control characters, newlines, and invalid TOML keys are blocked fail-closed to prevent config.toml injection.",
		DeepWhy:        ux.SanitizeTerminalText(detail),
		ExitCode:       10,
	})
}

func invalidTOMLError(configPath, target, detail string) error {
	base := filepath.Base(configPath)
	if base == "" || base == "." {
		base = "config.toml"
	}
	return &ux.FixForwardError{
		Tool:           "fabrial",
		Code:           "FABRIAL_INIT_MCP_INVALID_TOML",
		Summary:        fmt.Sprintf("Existing Codex config %s contains invalid TOML", base),
		RemediationCmd: fmt.Sprintf("fabrial init --mcp --target %s", target),
		WhyOneLiner:    "Refusing to overwrite a malformed Codex config.toml file; fix the TOML syntax first.",
		DeepWhy:        fmt.Sprintf("Failed to parse %s: %s", ux.SanitizeTerminalText(configPath), ux.SanitizeTerminalText(detail)),
		ExitCode:       1,
	}
}

func formatCodexMCPServerBlock(name string, spec MCPServerSpec) ([]string, error) {
	if err := validateTOMLKeySegment(name); err != nil {
		return nil, err
	}
	cmdStr, err := formatTOMLBasicString(spec.Command)
	if err != nil {
		return nil, err
	}
	argsStr, err := formatTOMLStringArray(spec.Args)
	if err != nil {
		return nil, err
	}
	return []string{
		fmt.Sprintf("[mcp_servers.%s]", name),
		fmt.Sprintf("command = %s", cmdStr),
		fmt.Sprintf("args = %s", argsStr),
	}, nil
}

func formatCodexMCPServerInline(lhs string, spec MCPServerSpec) (string, error) {
	cmdStr, err := formatTOMLBasicString(spec.Command)
	if err != nil {
		return "", err
	}
	argsStr, err := formatTOMLStringArray(spec.Args)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s = { command = %s, args = %s }", lhs, cmdStr, argsStr), nil
}

func formatTOMLStringArray(items []string) (string, error) {
	parts := make([]string, len(items))
	for i, item := range items {
		escaped, err := formatTOMLBasicString(item)
		if err != nil {
			return "", err
		}
		parts[i] = escaped
	}
	return "[" + strings.Join(parts, ", ") + "]", nil
}

// --- Strict Pure-Go TOML 1.0 Parser & Validator ---

type tomlParser struct {
	src         string
	pos         int
	line        int // 0-based line index
	root        *tomlNode
	currTable   *tomlNode
	currPath    []string
	sections    []tomlSection
	currSecIdx  int
	kvSpans     map[string]*tomlLineSpan
	dottedSpans map[string][]tomlLineSpan
}

func parseCodexTOML(data []byte, configPath string, target string) (*parsedCodexTOML, error) {
	if !utf8.Valid(data) {
		return nil, invalidTOMLError(configPath, target, "document is not valid UTF-8")
	}

	src := string(data)
	// Strip UTF-8 BOM if present? TOML 1.0 forbids BOM or treats it invalid; keep strict.
	lines, crErr := splitTOMLLines(src)
	if crErr != nil {
		return nil, invalidTOMLError(configPath, target, crErr.Error())
	}

	root := newTOMLTableNode(true)
	p := &tomlParser{
		src:         src,
		pos:         0,
		line:        0,
		root:        root,
		currTable:   root,
		currSecIdx:  -1,
		kvSpans:     make(map[string]*tomlLineSpan),
		dottedSpans: make(map[string][]tomlLineSpan),
	}

	if err := p.parseDocument(); err != nil {
		return nil, invalidTOMLError(configPath, target, err.Error())
	}
	if p.currSecIdx >= 0 {
		p.sections[p.currSecIdx].endLine = len(lines)
	}

	doc := &parsedCodexTOML{
		root:       p.root,
		lines:      lines,
		sections:   p.sections,
		mcpServers: make(map[string]*tomlMCPServerEntry),
	}

	if mcpNode, exists := p.root.children["mcp_servers"]; exists {
		if mcpNode.kind != tomlNodeTable && mcpNode.kind != tomlNodeInlineTable {
			return nil, invalidTOMLError(configPath, target, "top-level key \"mcp_servers\" must be a TOML table")
		}
		doc.hasMCPTable = true

		sectionIndexByServer := make(map[string]int)
		for idx, sec := range p.sections {
			if !sec.isArrayTable && len(sec.path) == 2 && sec.path[0] == "mcp_servers" {
				sectionIndexByServer[sec.path[1]] = idx
			}
		}

		for srvName, srvNode := range mcpNode.children {
			entry := &tomlMCPServerEntry{
				name:        srvName,
				sectionIdx:  -1,
				kvSpan:      p.kvSpans[srvName],
				dottedSpans: p.dottedSpans[srvName],
			}
			if idx, ok := sectionIndexByServer[srvName]; ok {
				entry.sectionIdx = idx
			}
			if srvNode.kind == tomlNodeTable || srvNode.kind == tomlNodeInlineTable {
				if cmdNode, ok := srvNode.children["command"]; ok && cmdNode.kind == tomlNodeValue {
					if s, ok := cmdNode.val.(string); ok {
						entry.command = s
						entry.hasCommand = true
					}
				}
				if argsNode, ok := srvNode.children["args"]; ok && argsNode.kind == tomlNodeValue {
					entry.hasArgs = true
					if arr, ok := argsNode.val.([]interface{}); ok {
						strArgs := make([]string, 0, len(arr))
						valid := true
						for _, elem := range arr {
							s, isStr := elem.(string)
							if !isStr {
								valid = false
								break
							}
							strArgs = append(strArgs, s)
						}
						if valid {
							entry.args = strArgs
							entry.argsValid = true
						}
					}
				}
			}
			doc.mcpServers[srvName] = entry
		}
	}

	return doc, nil
}

func splitTOMLLines(src string) ([]string, error) {
	if src == "" {
		return nil, nil
	}
	// Reject bare CR not followed by LF
	for i := 0; i < len(src); i++ {
		if src[i] == '\r' && (i+1 >= len(src) || src[i+1] != '\n') {
			return nil, errors.New("bare carriage return (CR) without LF is not valid TOML")
		}
	}
	trimmed := src
	if strings.HasSuffix(trimmed, "\r\n") {
		trimmed = trimmed[:len(trimmed)-2]
	} else if strings.HasSuffix(trimmed, "\n") {
		trimmed = trimmed[:len(trimmed)-1]
	}
	rawLines := strings.Split(trimmed, "\n")
	for i, l := range rawLines {
		rawLines[i] = strings.TrimSuffix(l, "\r")
	}
	return rawLines, nil
}

func (p *tomlParser) parseDocument() error {
	for p.pos < len(p.src) {
		p.skipHorizWS()
		if p.pos >= len(p.src) {
			break
		}
		ch := p.src[p.pos]
		if ch == '\n' || ch == '\r' {
			if err := p.consumeNewline(); err != nil {
				return err
			}
			continue
		}
		if ch == '#' {
			if err := p.skipComment(); err != nil {
				return err
			}
			if p.pos < len(p.src) {
				if err := p.consumeNewline(); err != nil {
					return err
				}
			}
			continue
		}
		if ch == '[' {
			if err := p.parseTableHeader(); err != nil {
				return err
			}
			continue
		}
		if err := p.parseKeyValueStatement(); err != nil {
			return err
		}
	}
	return nil
}

func (p *tomlParser) parseTableHeader() error {
	headerLine := p.line
	isArray := false
	p.pos++ // consume '['
	if p.pos < len(p.src) && p.src[p.pos] == '[' {
		isArray = true
		p.pos++
	}
	p.skipHorizWS()

	path, err := p.parseDottedKey()
	if err != nil {
		return fmt.Errorf("line %d: invalid table header: %w", headerLine+1, err)
	}

	p.skipHorizWS()
	if isArray {
		if p.pos+1 >= len(p.src) || p.src[p.pos] != ']' || p.src[p.pos+1] != ']' {
			return fmt.Errorf("line %d: unclosed array-of-tables header (expected ']]')", headerLine+1)
		}
		p.pos += 2
	} else {
		if p.pos >= len(p.src) || p.src[p.pos] != ']' {
			return fmt.Errorf("line %d: unclosed table header (expected ']')", headerLine+1)
		}
		p.pos++
	}

	if err := p.expectLineEnd(); err != nil {
		return fmt.Errorf("line %d: unexpected token after table header: %w", headerLine+1, err)
	}

	targetTable, err := p.defineTablePath(path, isArray)
	if err != nil {
		return fmt.Errorf("line %d: %w", headerLine+1, err)
	}

	if p.currSecIdx >= 0 {
		p.sections[p.currSecIdx].endLine = headerLine
	}
	p.sections = append(p.sections, tomlSection{
		path:            path,
		isArrayTable:    isArray,
		headerLine:      headerLine,
		lastContentLine: headerLine,
	})
	p.currSecIdx = len(p.sections) - 1
	p.currTable = targetTable
	p.currPath = path
	return nil
}

func (p *tomlParser) defineTablePath(path []string, isArray bool) (*tomlNode, error) {
	curr := p.root
	for i := 0; i < len(path)-1; i++ {
		seg := path[i]
		next, exists := curr.children[seg]
		if !exists {
			next = newTOMLTableNode(false)
			curr.children[seg] = next
			curr = next
			continue
		}
		switch next.kind {
		case tomlNodeTable:
			curr = next
		case tomlNodeArrayOfTables:
			curr = next.arrayTables[len(next.arrayTables)-1]
		default:
			return nil, fmt.Errorf("cannot define subtable under non-table key %q", seg)
		}
	}

	last := path[len(path)-1]
	if isArray {
		existing, exists := curr.children[last]
		if !exists {
			elem := newTOMLTableNode(true)
			curr.children[last] = &tomlNode{
				kind:        tomlNodeArrayOfTables,
				arrayTables: []*tomlNode{elem},
			}
			return elem, nil
		}
		if existing.kind != tomlNodeArrayOfTables {
			return nil, fmt.Errorf("cannot redefine non-array key %q as array-of-tables", last)
		}
		elem := newTOMLTableNode(true)
		existing.arrayTables = append(existing.arrayTables, elem)
		return elem, nil
	}

	existing, exists := curr.children[last]
	if !exists {
		tbl := newTOMLTableNode(true)
		curr.children[last] = tbl
		return tbl, nil
	}
	if existing.kind != tomlNodeTable {
		return nil, fmt.Errorf("cannot redefine key %q as table [%s]", last, strings.Join(path, "."))
	}
	if existing.definedExplicitly || existing.dottedDefined {
		return nil, fmt.Errorf("duplicate table header [%s]", strings.Join(path, "."))
	}
	existing.definedExplicitly = true
	return existing, nil
}

func (p *tomlParser) parseKeyValueStatement() error {
	startLine := p.line
	keyPath, err := p.parseDottedKey()
	if err != nil {
		return fmt.Errorf("line %d: %w", startLine+1, err)
	}
	p.skipHorizWS()
	if p.pos >= len(p.src) || p.src[p.pos] != '=' {
		return fmt.Errorf("line %d: expected '=' after key %q", startLine+1, strings.Join(keyPath, "."))
	}
	p.pos++ // consume '='
	p.skipHorizWS()
	if p.pos >= len(p.src) || p.src[p.pos] == '\n' || p.src[p.pos] == '\r' || p.src[p.pos] == '#' {
		return fmt.Errorf("line %d: missing value after '=' for key %q", startLine+1, strings.Join(keyPath, "."))
	}

	valNode, err := p.parseValue(0)
	if err != nil {
		return fmt.Errorf("line %d: %w", startLine+1, err)
	}
	endLine := p.line

	if err := p.expectLineEnd(); err != nil {
		return fmt.Errorf("line %d: unexpected trailing characters after value: %w", endLine+1, err)
	}

	if err := assignDottedKey(p.currTable, keyPath, valNode); err != nil {
		return fmt.Errorf("line %d: %w", startLine+1, err)
	}

	if p.currSecIdx >= 0 {
		p.sections[p.currSecIdx].lastContentLine = endLine
	}

	// Track non-section definitions of mcp_servers.<name> for surgical updates
	if len(p.currPath) == 1 && p.currPath[0] == "mcp_servers" {
		if len(keyPath) == 1 {
			p.kvSpans[keyPath[0]] = &tomlLineSpan{startLine: startLine, endLine: endLine, prefix: ""}
		} else if len(keyPath) > 1 {
			p.dottedSpans[keyPath[0]] = append(p.dottedSpans[keyPath[0]], tomlLineSpan{startLine: startLine, endLine: endLine})
		}
	} else if len(p.currPath) == 0 && len(keyPath) >= 2 && keyPath[0] == "mcp_servers" {
		if len(keyPath) == 2 {
			p.kvSpans[keyPath[1]] = &tomlLineSpan{startLine: startLine, endLine: endLine, prefix: "mcp_servers."}
		} else {
			p.dottedSpans[keyPath[1]] = append(p.dottedSpans[keyPath[1]], tomlLineSpan{startLine: startLine, endLine: endLine})
		}
	}

	return nil
}

func assignDottedKey(target *tomlNode, keyPath []string, valNode *tomlNode) error {
	curr := target
	for i := 0; i < len(keyPath)-1; i++ {
		seg := keyPath[i]
		next, exists := curr.children[seg]
		if !exists {
			next = newTOMLTableNode(false)
			next.dottedDefined = true
			curr.children[seg] = next
			curr = next
			continue
		}
		if next.kind != tomlNodeTable {
			return fmt.Errorf("cannot assign dotted key into non-table %q", seg)
		}
		if next.definedExplicitly {
			return fmt.Errorf("cannot extend explicitly defined table %q with dotted key", seg)
		}
		next.dottedDefined = true
		curr = next
	}
	last := keyPath[len(keyPath)-1]
	if _, exists := curr.children[last]; exists {
		return fmt.Errorf("duplicate key %q", strings.Join(keyPath, "."))
	}
	curr.children[last] = valNode
	return nil
}

func (p *tomlParser) parseDottedKey() ([]string, error) {
	var parts []string
	for {
		seg, err := p.parseKeySegment()
		if err != nil {
			return nil, err
		}
		parts = append(parts, seg)
		p.skipHorizWS()
		if p.pos < len(p.src) && p.src[p.pos] == '.' {
			p.pos++
			p.skipHorizWS()
			continue
		}
		break
	}
	return parts, nil
}

func (p *tomlParser) parseKeySegment() (string, error) {
	if p.pos >= len(p.src) {
		return "", errors.New("unexpected EOF while parsing key")
	}
	switch p.src[p.pos] {
	case '"':
		if strings.HasPrefix(p.src[p.pos:], `"""`) {
			return "", errors.New("multi-line strings are not allowed as TOML keys")
		}
		return p.parseBasicString()
	case '\'':
		if strings.HasPrefix(p.src[p.pos:], `'''`) {
			return "", errors.New("multi-line literal strings are not allowed as TOML keys")
		}
		return p.parseLiteralString()
	default:
		start := p.pos
		for p.pos < len(p.src) {
			c := p.src[p.pos]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
				p.pos++
			} else {
				break
			}
		}
		if p.pos == start {
			return "", fmt.Errorf("invalid key character %q", p.src[p.pos])
		}
		return p.src[start:p.pos], nil
	}
}

func (p *tomlParser) parseValue(depth int) (*tomlNode, error) {
	if depth > maxTOMLNestingDepth {
		return nil, errors.New("TOML value nesting depth exceeded")
	}
	if p.pos >= len(p.src) {
		return nil, errors.New("unexpected EOF while parsing value")
	}
	ch := p.src[p.pos]
	switch ch {
	case '"':
		if strings.HasPrefix(p.src[p.pos:], `"""`) {
			s, err := p.parseMultilineBasicString()
			if err != nil {
				return nil, err
			}
			return &tomlNode{kind: tomlNodeValue, val: s}, nil
		}
		s, err := p.parseBasicString()
		if err != nil {
			return nil, err
		}
		return &tomlNode{kind: tomlNodeValue, val: s}, nil
	case '\'':
		if strings.HasPrefix(p.src[p.pos:], `'''`) {
			s, err := p.parseMultilineLiteralString()
			if err != nil {
				return nil, err
			}
			return &tomlNode{kind: tomlNodeValue, val: s}, nil
		}
		s, err := p.parseLiteralString()
		if err != nil {
			return nil, err
		}
		return &tomlNode{kind: tomlNodeValue, val: s}, nil
	case '[':
		arr, err := p.parseArray(depth + 1)
		if err != nil {
			return nil, err
		}
		return &tomlNode{kind: tomlNodeValue, val: arr}, nil
	case '{':
		return p.parseInlineTable(depth + 1)
	default:
		v, err := p.parseBareScalar()
		if err != nil {
			return nil, err
		}
		return &tomlNode{kind: tomlNodeValue, val: v}, nil
	}
}

func (p *tomlParser) parseBasicString() (string, error) {
	p.pos++ // opening '"'
	var b strings.Builder
	for p.pos < len(p.src) {
		ch := p.src[p.pos]
		if ch == '"' {
			p.pos++
			return b.String(), nil
		}
		if ch == '\n' || ch == '\r' {
			return "", errors.New("unclosed basic string before end of line")
		}
		if ch == '\\' {
			r, err := p.parseEscapeSequence()
			if err != nil {
				return "", err
			}
			b.WriteRune(r)
			continue
		}
		if ch < 0x20 && ch != '\t' || ch == 0x7f {
			return "", fmt.Errorf("unescaped control character 0x%02x in basic string", ch)
		}
		r, size := utf8.DecodeRuneInString(p.src[p.pos:])
		b.WriteRune(r)
		p.pos += size
	}
	return "", errors.New("unclosed basic string at EOF")
}

func (p *tomlParser) parseMultilineBasicString() (string, error) {
	p.pos += 3 // opening '"""'
	// Trim immediate newline after opening delimiter
	if p.pos < len(p.src) && (p.src[p.pos] == '\n' || p.src[p.pos] == '\r') {
		if err := p.consumeNewline(); err != nil {
			return "", err
		}
	}
	var b strings.Builder
	for p.pos < len(p.src) {
		ch := p.src[p.pos]
		if ch == '"' {
			quoteCount := 0
			for p.pos+quoteCount < len(p.src) && p.src[p.pos+quoteCount] == '"' {
				quoteCount++
			}
			if quoteCount >= 6 {
				return "", errors.New("too many consecutive quotes in multi-line basic string")
			}
			if quoteCount >= 3 {
				for i := 0; i < quoteCount-3; i++ {
					b.WriteByte('"')
				}
				p.pos += quoteCount
				return b.String(), nil
			}
			for i := 0; i < quoteCount; i++ {
				b.WriteByte('"')
			}
			p.pos += quoteCount
			continue
		}
		if ch == '\\' {
			// Check for line-ending backslash
			look := p.pos + 1
			for look < len(p.src) && (p.src[look] == ' ' || p.src[look] == '\t') {
				look++
			}
			if look < len(p.src) && (p.src[look] == '\n' || p.src[look] == '\r') {
				p.pos = look
				if err := p.consumeNewline(); err != nil {
					return "", err
				}
				for p.pos < len(p.src) {
					c := p.src[p.pos]
					if c == ' ' || c == '\t' {
						p.pos++
					} else if c == '\n' || c == '\r' {
						if err := p.consumeNewline(); err != nil {
							return "", err
						}
					} else {
						break
					}
				}
				continue
			}
			r, err := p.parseEscapeSequence()
			if err != nil {
				return "", err
			}
			b.WriteRune(r)
			continue
		}
		if ch == '\n' || ch == '\r' {
			if err := p.consumeNewline(); err != nil {
				return "", err
			}
			b.WriteByte('\n')
			continue
		}
		if ch < 0x20 && ch != '\t' || ch == 0x7f {
			return "", fmt.Errorf("unescaped control character 0x%02x in multi-line basic string", ch)
		}
		r, size := utf8.DecodeRuneInString(p.src[p.pos:])
		b.WriteRune(r)
		p.pos += size
	}
	return "", errors.New("unclosed multi-line basic string at EOF")
}

func (p *tomlParser) parseEscapeSequence() (rune, error) {
	p.pos++ // consume '\'
	if p.pos >= len(p.src) {
		return 0, errors.New("unterminated escape sequence at EOF")
	}
	ch := p.src[p.pos]
	p.pos++
	switch ch {
	case 'b':
		return '\b', nil
	case 't':
		return '\t', nil
	case 'n':
		return '\n', nil
	case 'f':
		return '\f', nil
	case 'r':
		return '\r', nil
	case '"':
		return '"', nil
	case '\\':
		return '\\', nil
	case 'u':
		return p.parseUnicodeEscape(4)
	case 'U':
		return p.parseUnicodeEscape(8)
	default:
		return 0, fmt.Errorf("invalid escape sequence '\\%c'", ch)
	}
}

func (p *tomlParser) parseUnicodeEscape(hexDigits int) (rune, error) {
	if p.pos+hexDigits > len(p.src) {
		return 0, fmt.Errorf("truncated unicode escape sequence (expected %d hex digits)", hexDigits)
	}
	hexStr := p.src[p.pos : p.pos+hexDigits]
	p.pos += hexDigits
	v, err := strconv.ParseUint(hexStr, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid unicode escape hex %q", hexStr)
	}
	r := rune(v)
	if r > 0x10FFFF || (r >= 0xD800 && r <= 0xDFFF) {
		return 0, fmt.Errorf("invalid unicode scalar value U+%04X", r)
	}
	return r, nil
}

func (p *tomlParser) parseLiteralString() (string, error) {
	p.pos++ // opening '\''
	start := p.pos
	for p.pos < len(p.src) {
		ch := p.src[p.pos]
		if ch == '\'' {
			s := p.src[start:p.pos]
			p.pos++
			return s, nil
		}
		if ch == '\n' || ch == '\r' {
			return "", errors.New("unclosed literal string before end of line")
		}
		if ch < 0x20 && ch != '\t' || ch == 0x7f {
			return "", fmt.Errorf("disallowed control character 0x%02x in literal string", ch)
		}
		p.pos++
	}
	return "", errors.New("unclosed literal string at EOF")
}

func (p *tomlParser) parseMultilineLiteralString() (string, error) {
	p.pos += 3 // opening "'''"
	if p.pos < len(p.src) && (p.src[p.pos] == '\n' || p.src[p.pos] == '\r') {
		if err := p.consumeNewline(); err != nil {
			return "", err
		}
	}
	var b strings.Builder
	for p.pos < len(p.src) {
		ch := p.src[p.pos]
		if ch == '\'' {
			quoteCount := 0
			for p.pos+quoteCount < len(p.src) && p.src[p.pos+quoteCount] == '\'' {
				quoteCount++
			}
			if quoteCount >= 6 {
				return "", errors.New("too many consecutive single quotes in multi-line literal string")
			}
			if quoteCount >= 3 {
				for i := 0; i < quoteCount-3; i++ {
					b.WriteByte('\'')
				}
				p.pos += quoteCount
				return b.String(), nil
			}
			for i := 0; i < quoteCount; i++ {
				b.WriteByte('\'')
			}
			p.pos += quoteCount
			continue
		}
		if ch == '\n' || ch == '\r' {
			if err := p.consumeNewline(); err != nil {
				return "", err
			}
			b.WriteByte('\n')
			continue
		}
		if ch < 0x20 && ch != '\t' || ch == 0x7f {
			return "", fmt.Errorf("disallowed control character 0x%02x in multi-line literal string", ch)
		}
		r, size := utf8.DecodeRuneInString(p.src[p.pos:])
		b.WriteRune(r)
		p.pos += size
	}
	return "", errors.New("unclosed multi-line literal string at EOF")
}

func (p *tomlParser) parseArray(depth int) ([]interface{}, error) {
	p.pos++ // consume '['
	arr := make([]interface{}, 0)
	for {
		if err := p.skipWSAndCommentsMultiline(); err != nil {
			return nil, err
		}
		if p.pos >= len(p.src) {
			return nil, errors.New("unclosed array '[' at EOF")
		}
		if p.src[p.pos] == ']' {
			p.pos++
			return arr, nil
		}
		valNode, err := p.parseValue(depth)
		if err != nil {
			return nil, err
		}
		if valNode.kind == tomlNodeValue {
			arr = append(arr, valNode.val)
		} else {
			arr = append(arr, valNode)
		}
		if err := p.skipWSAndCommentsMultiline(); err != nil {
			return nil, err
		}
		if p.pos >= len(p.src) {
			return nil, errors.New("unclosed array '[' at EOF")
		}
		if p.src[p.pos] == ',' {
			p.pos++
			continue
		}
		if p.src[p.pos] == ']' {
			p.pos++
			return arr, nil
		}
		return nil, fmt.Errorf("expected ',' or ']' in array, got %q", p.src[p.pos])
	}
}

func (p *tomlParser) parseInlineTable(depth int) (*tomlNode, error) {
	p.pos++ // consume '{'
	tbl := &tomlNode{
		kind:              tomlNodeInlineTable,
		definedExplicitly: true,
		children:          make(map[string]*tomlNode),
	}
	p.skipHorizWS()
	if p.pos >= len(p.src) {
		return nil, errors.New("unclosed inline table '{' at EOF")
	}
	if p.src[p.pos] == '}' {
		p.pos++
		return tbl, nil
	}
	for {
		p.skipHorizWS()
		if p.pos >= len(p.src) {
			return nil, errors.New("unclosed inline table '{' at EOF")
		}
		if p.src[p.pos] == '\n' || p.src[p.pos] == '\r' {
			return nil, errors.New("newlines are not allowed inside inline tables")
		}
		keyPath, err := p.parseDottedKey()
		if err != nil {
			return nil, fmt.Errorf("inline table key: %w", err)
		}
		p.skipHorizWS()
		if p.pos >= len(p.src) || p.src[p.pos] != '=' {
			return nil, fmt.Errorf("expected '=' in inline table after key %q", strings.Join(keyPath, "."))
		}
		p.pos++
		p.skipHorizWS()
		valNode, err := p.parseValue(depth)
		if err != nil {
			return nil, err
		}
		if err := assignDottedKey(tbl, keyPath, valNode); err != nil {
			return nil, fmt.Errorf("inline table: %w", err)
		}
		p.skipHorizWS()
		if p.pos >= len(p.src) {
			return nil, errors.New("unclosed inline table '{' at EOF")
		}
		if p.src[p.pos] == ',' {
			p.pos++
			p.skipHorizWS()
			if p.pos < len(p.src) && p.src[p.pos] == '}' {
				return nil, errors.New("trailing comma is not allowed in inline table")
			}
			continue
		}
		if p.src[p.pos] == '}' {
			p.pos++
			return tbl, nil
		}
		return nil, fmt.Errorf("expected ',' or '}' in inline table, got %q", p.src[p.pos])
	}
}

func (p *tomlParser) parseBareScalar() (interface{}, error) {
	start := p.pos
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' || c == ']' || c == '}' || c == '#' {
			break
		}
		p.pos++
	}
	tok := p.src[start:p.pos]
	if tok == "" {
		return nil, errors.New("empty TOML value")
	}

	// Support RFC 3339 date-time with a space separator (e.g. 1979-05-27 07:32:00Z)
	if isLocalDate(tok) && p.pos < len(p.src) && p.src[p.pos] == ' ' {
		savePos := p.pos
		p.pos++ // space
		tStart := p.pos
		for p.pos < len(p.src) {
			c := p.src[p.pos]
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' || c == ']' || c == '}' || c == '#' {
				break
			}
			p.pos++
		}
		timePart := p.src[tStart:p.pos]
		if isTimeWithOptionalOffset(timePart) {
			return tok + " " + timePart, nil
		}
		p.pos = savePos
		return tok, nil
	}

	switch tok {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "inf", "+inf":
		return math.Inf(1), nil
	case "-inf":
		return math.Inf(-1), nil
	case "nan", "+nan", "-nan":
		return math.NaN(), nil
	}

	if isTOMLDateTime(tok) || isLocalDate(tok) || isLocalTime(tok) {
		return tok, nil
	}

	if iv, ok := parseTOMLInt(tok); ok {
		return iv, nil
	}
	if fv, ok := parseTOMLFloat(tok); ok {
		return fv, nil
	}

	return nil, fmt.Errorf("invalid TOML value %q", tok)
}

func parseTOMLInt(tok string) (int64, bool) {
	if tok == "" {
		return 0, false
	}
	// Prefixed integer bases (no sign allowed per TOML 1.0)
	if len(tok) > 2 && tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'o' || tok[1] == 'b') {
		base := 16
		switch tok[1] {
		case 'o':
			base = 8
		case 'b':
			base = 2
		}
		digits := tok[2:]
		if !validUnderscoredDigits(digits, base) {
			return 0, false
		}
		clean := strings.ReplaceAll(digits, "_", "")
		v, err := strconv.ParseInt(clean, base, 64)
		if err != nil {
			// Accept large unsigned hex/oct/bin literals as int64 boundary check via ParseUint
			if uv, uErr := strconv.ParseUint(clean, base, 64); uErr == nil {
				return int64(uv), true
			}
			return 0, false
		}
		return v, true
	}

	s := tok
	if s[0] == '+' || s[0] == '-' {
		s = s[1:]
	}
	if len(s) == 0 {
		return 0, false
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, false // leading zeros disallowed in TOML decimal integers
	}
	if !validUnderscoredDigits(s, 10) {
		return 0, false
	}
	clean := strings.ReplaceAll(tok, "_", "")
	v, err := strconv.ParseInt(clean, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func parseTOMLFloat(tok string) (float64, bool) {
	if tok == "" {
		return 0, false
	}
	if !strings.ContainsAny(tok, ".eE") {
		return 0, false
	}
	s := tok
	if s[0] == '+' || s[0] == '-' {
		s = s[1:]
	}
	if s == "" {
		return 0, false
	}

	// Split exponent part if present
	expIdx := strings.IndexAny(s, "eE")
	mantissa := s
	expPart := ""
	if expIdx >= 0 {
		mantissa = s[:expIdx]
		expPart = s[expIdx+1:]
		if expPart == "" {
			return 0, false
		}
		if expPart[0] == '+' || expPart[0] == '-' {
			expPart = expPart[1:]
		}
		if !validUnderscoredDigits(expPart, 10) {
			return 0, false
		}
	}

	dotIdx := strings.IndexByte(mantissa, '.')
	if dotIdx >= 0 {
		intPart := mantissa[:dotIdx]
		fracPart := mantissa[dotIdx+1:]
		if intPart == "" || fracPart == "" {
			return 0, false
		}
		if len(intPart) > 1 && intPart[0] == '0' {
			return 0, false
		}
		if !validUnderscoredDigits(intPart, 10) || !validUnderscoredDigits(fracPart, 10) {
			return 0, false
		}
	} else {
		if len(mantissa) > 1 && mantissa[0] == '0' {
			return 0, false
		}
		if !validUnderscoredDigits(mantissa, 10) {
			return 0, false
		}
	}

	clean := strings.ReplaceAll(tok, "_", "")
	v, err := strconv.ParseFloat(clean, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func validUnderscoredDigits(s string, base int) bool {
	if s == "" || s[0] == '_' || s[len(s)-1] == '_' {
		return false
	}
	prevUnderscore := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' {
			if prevUnderscore {
				return false
			}
			prevUnderscore = true
			continue
		}
		prevUnderscore = false
		switch base {
		case 2:
			if c != '0' && c != '1' {
				return false
			}
		case 8:
			if c < '0' || c > '7' {
				return false
			}
		case 10:
			if c < '0' || c > '9' {
				return false
			}
		case 16:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

func isLocalDate(s string) bool {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return false
	}
	return isDigits(s[0:4]) && isDigits(s[5:7]) && isDigits(s[8:10])
}

func isLocalTime(s string) bool {
	if len(s) < 8 || s[2] != ':' || s[5] != ':' {
		return false
	}
	if !isDigits(s[0:2]) || !isDigits(s[3:5]) || !isDigits(s[6:8]) {
		return false
	}
	if len(s) == 8 {
		return true
	}
	return s[8] == '.' && len(s) > 9 && isDigits(s[9:])
}

func isTimeWithOptionalOffset(s string) bool {
	if isLocalTime(s) {
		return true
	}
	if len(s) < 9 {
		return false
	}
	if s[len(s)-1] == 'Z' || s[len(s)-1] == 'z' {
		return isLocalTime(s[:len(s)-1])
	}
	if len(s) >= 14 {
		offIdx := len(s) - 6
		if (s[offIdx] == '+' || s[offIdx] == '-') && s[offIdx+3] == ':' &&
			isDigits(s[offIdx+1:offIdx+3]) && isDigits(s[offIdx+4:offIdx+6]) {
			return isLocalTime(s[:offIdx])
		}
	}
	return false
}

func isTOMLDateTime(s string) bool {
	if len(s) < 19 {
		return false
	}
	if !isLocalDate(s[:10]) {
		return false
	}
	if s[10] != 'T' && s[10] != 't' {
		return false
	}
	return isTimeWithOptionalOffset(s[11:])
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func (p *tomlParser) skipHorizWS() {
	for p.pos < len(p.src) && (p.src[p.pos] == ' ' || p.src[p.pos] == '\t') {
		p.pos++
	}
}

func (p *tomlParser) skipComment() error {
	for p.pos < len(p.src) {
		ch := p.src[p.pos]
		if ch == '\n' || ch == '\r' {
			return nil
		}
		if ch < 0x20 && ch != '\t' || ch == 0x7f {
			return fmt.Errorf("line %d: invalid control character 0x%02x in comment", p.line+1, ch)
		}
		p.pos++
	}
	return nil
}

func (p *tomlParser) consumeNewline() error {
	if p.pos >= len(p.src) {
		return nil
	}
	if p.src[p.pos] == '\r' {
		if p.pos+1 >= len(p.src) || p.src[p.pos+1] != '\n' {
			return fmt.Errorf("line %d: bare CR without LF", p.line+1)
		}
		p.pos += 2
		p.line++
		return nil
	}
	if p.src[p.pos] == '\n' {
		p.pos++
		p.line++
		return nil
	}
	return fmt.Errorf("line %d: expected newline", p.line+1)
}

func (p *tomlParser) expectLineEnd() error {
	p.skipHorizWS()
	if p.pos >= len(p.src) {
		return nil
	}
	if p.src[p.pos] == '#' {
		if err := p.skipComment(); err != nil {
			return err
		}
	}
	if p.pos >= len(p.src) {
		return nil
	}
	if p.src[p.pos] == '\n' || p.src[p.pos] == '\r' {
		return p.consumeNewline()
	}
	return fmt.Errorf("unexpected character %q", p.src[p.pos])
}

func (p *tomlParser) skipWSAndCommentsMultiline() error {
	for p.pos < len(p.src) {
		ch := p.src[p.pos]
		if ch == ' ' || ch == '\t' {
			p.pos++
			continue
		}
		if ch == '\n' || ch == '\r' {
			if err := p.consumeNewline(); err != nil {
				return err
			}
			continue
		}
		if ch == '#' {
			if err := p.skipComment(); err != nil {
				return err
			}
			continue
		}
		break
	}
	return nil
}
