package policy

import (
	"path/filepath"
	"strings"
	"unicode"
)

const maxWrapperDepth = 16

// NormalizeBinaryName extracts the lowercase base executable name, strips .exe,
// and normalizes versioned interpreter/runtime binaries (e.g. python3.12 -> python3, node20 -> node).
func NormalizeBinaryName(raw string) string {
	base := strings.ToLower(strings.TrimSpace(filepath.Base(raw)))
	base = strings.TrimSuffix(base, ".exe")
	if base == "" {
		return ""
	}

	if base == "nodejs" {
		return "node"
	}

	// Specific python/pip families where major version 3 is distinct in policy lists
	if rest, ok := strings.CutPrefix(base, "python3"); ok {
		if rest == "" || isVersionTail(rest) {
			return "python3"
		}
	}
	if rest, ok := strings.CutPrefix(base, "python2"); ok {
		if rest == "" || isVersionTail(rest) {
			return "python"
		}
	}
	if rest, ok := strings.CutPrefix(base, "pip3"); ok {
		if rest == "" || isVersionTail(rest) {
			return "pip3"
		}
	}
	if rest, ok := strings.CutPrefix(base, "pip2"); ok {
		if rest == "" || isVersionTail(rest) {
			return "pip"
		}
	}

	prefixes := []string{
		"python", "pip", "node", "ruby", "perl", "php", "lua",
		"bash", "zsh", "dash", "ksh",
		"clang++", "clang", "g++", "gcc", "rustc", "go",
		"bun", "deno", "uv", "cargo", "npm", "pnpm", "yarn",
	}
	for _, p := range prefixes {
		if base == p {
			return p
		}
		if rest, ok := strings.CutPrefix(base, p); ok && isVersionTail(rest) {
			return p
		}
	}

	return base
}

func isVersionTail(rest string) bool {
	if rest == "" {
		return false
	}
	if rest[0] == '-' || rest[0] == '.' {
		rest = rest[1:]
	}
	if rest == "" {
		return false
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return rest[0] >= '0' && rest[0] <= '9'
}

func isEnvAssignment(tok string) bool {
	eq := strings.IndexByte(tok, '=')
	if eq <= 0 {
		return false
	}
	name := tok[:eq]
	for i := 0; i < len(name); i++ {
		c := name[i]
		if i == 0 {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
				return false
			}
		} else {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
				return false
			}
		}
	}
	return true
}

// UnwrapCommands recursively peels leading KEY=VAL assignments and command wrappers
// (env, command, nohup, nice, timeout, stdbuf, xargs, and sh/bash/zsh -c scripts).
// It returns ordered command candidates (outer shells + unwrapped inner commands) so
// policy evaluation can enforce the strictest matching tier across all layers.
func UnwrapCommands(cmdArgs []string) ([][]string, bool) {
	var out [][]string
	exceeded := unwrapRecursive(cmdArgs, 0, &out)
	return out, exceeded
}

func unwrapRecursive(args []string, depth int, out *[][]string) bool {
	if depth > maxWrapperDepth {
		return true
	}

	// Strip leading ambient KEY=VAL tokens (e.g. "FOO=bar git clone ...")
	for len(args) > 0 && isEnvAssignment(args[0]) {
		args = args[1:]
		depth++
		if depth > maxWrapperDepth {
			return true
		}
	}
	if len(args) == 0 {
		return false
	}

	bin := NormalizeBinaryName(args[0])

	switch bin {
	case "env":
		inner := unwrapEnvArgs(args[1:])
		if len(inner) == 0 {
			*out = append(*out, args)
			return false
		}
		return unwrapRecursive(inner, depth+1, out)

	case "command":
		inner, inspectOnly := unwrapCommandBuiltin(args[1:])
		if inspectOnly || len(inner) == 0 {
			*out = append(*out, args)
			return false
		}
		return unwrapRecursive(inner, depth+1, out)

	case "nohup":
		inner := args[1:]
		if len(inner) > 0 && inner[0] == "--" {
			inner = inner[1:]
		}
		if len(inner) == 0 {
			*out = append(*out, args)
			return false
		}
		return unwrapRecursive(inner, depth+1, out)

	case "nice":
		inner := unwrapNiceArgs(args[1:])
		if len(inner) == 0 {
			*out = append(*out, args)
			return false
		}
		return unwrapRecursive(inner, depth+1, out)

	case "timeout":
		inner := unwrapTimeoutArgs(args[1:])
		if len(inner) == 0 {
			*out = append(*out, args)
			return false
		}
		return unwrapRecursive(inner, depth+1, out)

	case "stdbuf":
		inner := unwrapStdbufArgs(args[1:])
		if len(inner) == 0 {
			*out = append(*out, args)
			return false
		}
		return unwrapRecursive(inner, depth+1, out)

	case "xargs":
		// Keep xargs itself as a candidate AND unwrap target command if present
		*out = append(*out, args)
		inner := unwrapXargsArgs(args[1:])
		if len(inner) > 0 {
			return unwrapRecursive(inner, depth+1, out)
		}
		return false

	case "sh", "bash", "zsh", "dash", "ksh":
		// Always record the shell invocation itself AND unwrap -c script segments
		*out = append(*out, args)
		if script, ok := extractShellDashC(args[1:]); ok {
			segments := splitShellSegments(script)
			for _, seg := range segments {
				if len(seg) > 0 {
					if unwrapRecursive(seg, depth+1, out) {
						return true
					}
				}
			}
		}
		return false
	}

	*out = append(*out, args)
	return false
}

func unwrapEnvArgs(args []string) []string {
	for len(args) > 0 {
		a := args[0]
		if a == "--" {
			return args[1:]
		}
		if isEnvAssignment(a) {
			args = args[1:]
			continue
		}
		if a == "-S" || a == "--split-string" {
			if len(args) >= 2 {
				split := tokenizeShellWords(args[1])
				return append(split, args[2:]...)
			}
			return nil
		}
		if rest, ok := strings.CutPrefix(a, "--split-string="); ok {
			split := tokenizeShellWords(rest)
			return append(split, args[1:]...)
		}
		if rest, ok := strings.CutPrefix(a, "-S"); ok && rest != "" {
			split := tokenizeShellWords(rest)
			return append(split, args[1:]...)
		}
		if a == "-u" || a == "--unset" || a == "-C" || a == "--chdir" {
			if len(args) >= 2 {
				args = args[2:]
				continue
			}
			return nil
		}
		if strings.HasPrefix(a, "-") {
			args = args[1:]
			continue
		}
		break
	}
	return args
}

func unwrapCommandBuiltin(args []string) ([]string, bool) {
	inspectOnly := false
	for len(args) > 0 {
		a := args[0]
		if a == "--" {
			args = args[1:]
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			break
		}
		if strings.ContainsRune(a, 'v') || strings.ContainsRune(a, 'V') {
			inspectOnly = true
		}
		args = args[1:]
	}
	return args, inspectOnly
}

func unwrapNiceArgs(args []string) []string {
	for len(args) > 0 {
		a := args[0]
		if a == "--" {
			return args[1:]
		}
		if a == "-n" || a == "--adjustment" {
			if len(args) >= 2 {
				args = args[2:]
				continue
			}
			return nil
		}
		if strings.HasPrefix(a, "-") {
			args = args[1:]
			continue
		}
		break
	}
	return args
}

func unwrapTimeoutArgs(args []string) []string {
	for len(args) > 0 {
		a := args[0]
		if a == "--" {
			args = args[1:]
			break
		}
		if a == "-k" || a == "--kill-after" || a == "-s" || a == "--signal" {
			if len(args) >= 2 {
				args = args[2:]
				continue
			}
			return nil
		}
		if strings.HasPrefix(a, "-") {
			args = args[1:]
			continue
		}
		break
	}
	// First positional argument to timeout is the duration
	if len(args) > 0 {
		return args[1:]
	}
	return nil
}

func unwrapStdbufArgs(args []string) []string {
	for len(args) > 0 {
		a := args[0]
		if a == "--" {
			return args[1:]
		}
		if a == "-i" || a == "--input" || a == "-o" || a == "--output" || a == "-e" || a == "--error" {
			if len(args) >= 2 {
				args = args[2:]
				continue
			}
			return nil
		}
		if strings.HasPrefix(a, "-") {
			args = args[1:]
			continue
		}
		break
	}
	return args
}

func unwrapXargsArgs(args []string) []string {
	takesValue := map[string]bool{
		"-I": true, "-J": true, "-L": true, "-n": true, "-P": true,
		"-s": true, "-d": true, "-a": true, "-E": true,
		"--arg-file": true, "--delimiter": true, "--eof": true,
		"--max-args": true, "--max-lines": true, "--max-procs": true,
		"--max-chars": true, "--process-slot-var": true, "--replace": true,
	}
	for len(args) > 0 {
		a := args[0]
		if a == "--" {
			return args[1:]
		}
		if takesValue[a] {
			if len(args) >= 2 {
				args = args[2:]
				continue
			}
			return nil
		}
		if strings.HasPrefix(a, "-") {
			args = args[1:]
			continue
		}
		break
	}
	return args
}

func extractShellDashC(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if a == "-o" || a == "+o" || a == "--rcfile" || a == "--init-file" {
			i++
			continue
		}
		if a == "-c" {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		}
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.ContainsRune(a[1:], 'c') {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		}
		if !strings.HasPrefix(a, "-") {
			break
		}
	}
	return "", false
}

func splitShellSegments(script string) [][]string {
	var segments [][]string
	var cur strings.Builder
	inSingle := false
	inDouble := false
	escaped := false

	flush := func() {
		toks := tokenizeShellWords(cur.String())
		if len(toks) > 0 {
			segments = append(segments, toks)
		}
		cur.Reset()
	}

	for i := 0; i < len(script); i++ {
		c := script[i]
		if escaped {
			cur.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' && !inSingle {
			escaped = true
			cur.WriteByte(c)
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			cur.WriteByte(c)
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			cur.WriteByte(c)
			continue
		}
		if !inSingle {
			if c == '`' {
				flush()
				continue
			}
			if c == '$' && i+1 < len(script) && script[i+1] == '(' {
				flush()
				i++
				continue
			}
		}
		if !inSingle && !inDouble {
			if c == ';' || c == '|' || c == '&' || c == '\n' || c == ')' || c == '(' {
				flush()
				continue
			}
		}
		cur.WriteByte(c)
	}
	flush()
	return segments
}

func tokenizeShellWords(s string) []string {
	var words []string
	var cur strings.Builder
	inToken := false
	inSingle := false
	inDouble := false
	escaped := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			cur.WriteByte(c)
			inToken = true
			escaped = false
			continue
		}
		if c == '\\' && !inSingle {
			escaped = true
			inToken = true
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			inToken = true
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			inToken = true
			continue
		}
		if !inSingle && !inDouble && unicode.IsSpace(rune(c)) {
			if inToken {
				words = append(words, cur.String())
				cur.Reset()
				inToken = false
			}
			continue
		}
		cur.WriteByte(c)
		inToken = true
	}
	if inToken {
		words = append(words, cur.String())
	}
	return words
}

// CanonicalizeCommand normalizes the binary basename and strips global option flags
// preceding a subcommand (e.g. "go -C dir get pkg" -> "go get pkg", "git -C dir clone u" -> "git clone u").
func CanonicalizeCommand(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	bin := NormalizeBinaryName(args[0])
	rest := args[1:]

	switch bin {
	case "go":
		rest = stripLeadingFlags(rest, map[string]bool{"-C": true})
	case "git":
		rest = stripLeadingFlags(rest, map[string]bool{
			"-C": true, "-c": true, "--git-dir": true, "--work-tree": true,
			"--namespace": true, "--super-prefix": true, "--config-env": true, "--exec-path": true,
		})
	case "pnpm":
		rest = stripLeadingFlags(rest, map[string]bool{
			"-C": true, "--dir": true, "-F": true, "--filter": true,
		})
	case "npm":
		rest = stripLeadingFlags(rest, map[string]bool{
			"-C": true, "--prefix": true, "-w": true, "--workspace": true,
		})
	case "yarn":
		rest = stripLeadingFlags(rest, map[string]bool{"--cwd": true})
	case "cargo":
		// Cargo also accepts +<toolchain> before subcommand
		for len(rest) > 0 && strings.HasPrefix(rest[0], "+") {
			rest = rest[1:]
		}
		rest = stripLeadingFlags(rest, map[string]bool{
			"-C": true, "--manifest-path": true, "--config": true, "-Z": true, "--color": true,
		})
	case "uv":
		rest = stripLeadingFlags(rest, map[string]bool{
			"--directory": true, "--project": true, "--config-file": true, "--color": true,
		})
	case "pipx":
		rest = stripLeadingFlags(rest, nil)
	}

	out := make([]string, 0, 1+len(rest))
	out = append(out, bin)
	out = append(out, rest...)
	return out
}

func stripLeadingFlags(args []string, valueFlags map[string]bool) []string {
	for len(args) > 0 {
		a := args[0]
		if a == "--" {
			return args[1:]
		}
		if valueFlags != nil && valueFlags[a] {
			if len(args) >= 2 {
				args = args[2:]
				continue
			}
			return nil
		}
		if strings.HasPrefix(a, "-") {
			args = args[1:]
			continue
		}
		break
	}
	return args
}

// WildcardMatch performs case-insensitive or pre-lowercased glob matching where '*'
// matches ANY sequence of characters INCLUDING '/' and '?' matches any single character INCLUDING '/'.
func WildcardMatch(pattern, s string) bool {
	pi, si := 0, 0
	starIdx := -1
	matchIdx := 0

	for si < len(s) {
		if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]) {
			pi++
			si++
		} else if pi < len(pattern) && pattern[pi] == '*' {
			starIdx = pi
			matchIdx = si
			pi++
		} else if starIdx != -1 {
			pi = starIdx + 1
			matchIdx++
			si = matchIdx
		} else {
			return false
		}
	}

	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
