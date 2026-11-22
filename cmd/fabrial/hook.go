package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bonjoski/fabrial/pkg/hooks"
	"github.com/bonjoski/fabrial/pkg/ux"
)

func handleHook(args []string) {
	code := runHook(args, os.Stdin, os.Stdout, os.Stderr)
	if code != 0 {
		os.Exit(code)
	}
}

func runHook(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		_, _ = fmt.Fprintln(stdout, `Usage:
  fabrial hook eval --client <claude|cursor|gemini> --event <pre-tool|post-tool> [--strict] [--worktree <dir>] [--debug]

Sub-5ms push-based native IDE lifecycle hook evaluator (Claude Code, Cursor, Gemini CLI).
Reads a bounded JSON hook payload (<=1MB, 50ms deadline) from stdin and emits ONLY a single
dialect-compliant JSON decision object to stdout.`)
		return 0
	}

	sub := args[0]
	if sub != "eval" {
		ffe := &ux.FixForwardError{
			Tool:           "fabrial",
			Code:           "FABRIAL_HOOK_UNKNOWN_SUBCOMMAND",
			Summary:        fmt.Sprintf("Unknown hook subcommand %q", sub),
			RemediationCmd: "fabrial hook eval --client claude --event pre-tool",
			WhyOneLiner:    "Supported hook subcommand is `eval`.",
			DeepWhy:        "Invoke `fabrial hook eval --client <claude|cursor|gemini> --event <pre-tool|post-tool>` from your IDE hook configuration.",
			ExitCode:       1,
		}
		_ = ffe.Render(stderr, false, false)
		return ffe.ExitCode
	}

	return runHookEval(args[1:], stdin, stdout, stderr)
}

func runHookEval(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	clientRaw := ""
	eventRaw := ""
	strict := false
	debug := false
	worktree := ""

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--client":
			if i+1 < len(args) {
				clientRaw = args[i+1]
				i++
			}
		case strings.HasPrefix(arg, "--client="):
			clientRaw = strings.TrimPrefix(arg, "--client=")
		case arg == "--event":
			if i+1 < len(args) {
				eventRaw = args[i+1]
				i++
			}
		case strings.HasPrefix(arg, "--event="):
			eventRaw = strings.TrimPrefix(arg, "--event=")
		case arg == "--strict":
			strict = true
		case arg == "--debug":
			debug = true
		case arg == "--worktree" || arg == "--dir" || arg == "-d":
			if i+1 < len(args) {
				worktree = args[i+1]
				i++
			}
		case strings.HasPrefix(arg, "--worktree="):
			worktree = strings.TrimPrefix(arg, "--worktree=")
		case strings.HasPrefix(arg, "--dir="):
			worktree = strings.TrimPrefix(arg, "--dir=")
		case arg == "help" || arg == "-h" || arg == "--help":
			_, _ = fmt.Fprintln(stdout, "Usage: fabrial hook eval --client <claude|cursor|gemini> --event <pre-tool|post-tool> [--strict] [--worktree <dir>] [--debug]")
			return 0
		}
	}

	client, err := hooks.ParseClientDialect(clientRaw)
	if err != nil {
		var ffe *ux.FixForwardError
		if errors.As(err, &ffe) {
			_ = ffe.Render(stderr, false, false)
			return ffe.ExitCode
		}
		_, _ = fmt.Fprintf(stderr, "fabrial hook eval: %v\n", err)
		return 1
	}

	event, err := hooks.ParseHookEvent(eventRaw)
	if err != nil {
		var ffe *ux.FixForwardError
		if errors.As(err, &ffe) {
			_ = ffe.Render(stderr, false, false)
			return ffe.ExitCode
		}
		_, _ = fmt.Fprintf(stderr, "fabrial hook eval: %v\n", err)
		return 1
	}

	in, readErr := hooks.ReadAndParseInput(stdin, client, event, hooks.DefaultMaxInputBytes, hooks.DefaultReadTimeout)
	if readErr != nil {
		if debug {
			_, _ = fmt.Fprintf(stderr, "fabrial hook eval debug: stdin read/parse failed: %v\n", readErr)
		}
		if event == hooks.EventPostTool {
			// Post-tool hooks never stall editing on empty or malformed stdin.
			code, rErr := hooks.RenderClientResponse(stdout, client, event, &hooks.Decision{
				Allow:   true,
				Code:    "FABRIAL_HOOK_POST_INPUT_SKIPPED",
				Summary: "Post-tool hook skipped due to empty or unreadable stdin payload.",
			})
			if rErr != nil {
				return 1
			}
			return code
		}

		// Pre-tool hooks fail closed while strictly emitting valid dialect JSON to stdout.
		decCode := "FABRIAL_HOOK_INVALID_INPUT"
		summary := "Blocked because pre-tool hook stdin JSON was malformed or empty (fail-closed)."
		if errors.Is(readErr, hooks.ErrInputTooLarge) {
			decCode = "FABRIAL_HOOK_INPUT_TOO_LARGE"
			summary = "Blocked because pre-tool hook stdin payload exceeded the 1MB safety cap."
		} else if errors.Is(readErr, hooks.ErrInputTimeout) {
			decCode = "FABRIAL_HOOK_INPUT_TIMEOUT"
			summary = "Blocked because pre-tool hook stdin exceeded the 50ms read deadline."
		}
		code, rErr := hooks.RenderClientResponse(stdout, client, event, &hooks.Decision{
			Allow:          false,
			Code:           decCode,
			Summary:        summary,
			RemediationCmd: "fabrial doctor",
			Why:            "Pre-tool security hooks fail closed on oversized, timed-out, or invalid JSON input.",
		})
		if rErr != nil {
			return 1
		}
		return code
	}

	eval := &hooks.DefaultEvaluator{
		WorktreeRoot: worktree,
		Strict:       strict,
	}

	dec, evalErr := eval.Evaluate(context.Background(), in)
	if evalErr != nil {
		if debug {
			_, _ = fmt.Fprintf(stderr, "fabrial hook eval debug: evaluation error: %v\n", evalErr)
		}
		dec = &hooks.Decision{
			Allow:          event == hooks.EventPostTool,
			Code:           "FABRIAL_HOOK_EVAL_ERROR",
			Summary:        "Hook evaluation encountered an internal error.",
			RemediationCmd: "fabrial doctor",
		}
	}

	exitCode, renderErr := hooks.RenderClientResponse(stdout, client, event, dec)
	if renderErr != nil {
		if debug {
			_, _ = fmt.Fprintf(stderr, "fabrial hook eval debug: render error: %v\n", renderErr)
		}
		return 1
	}
	return exitCode
}

// runInitHooks plans or atomically applies native IDE lifecycle hook configurations
// for Claude Code, Cursor, and Gemini CLI, designed to be called directly by runInit.
func runInitHooks(targetDir string, isGlobal, applyMode, asJSON, showWhy bool, targets []string, stdout, stderr io.Writer) int {
	report, err := hooks.PlanAndApplyHooks(hooks.HooksInitOptions{
		WorktreeDir: targetDir,
		Global:      isGlobal,
		Apply:       applyMode,
		Targets:     targets,
	})
	if err != nil {
		var ffe *ux.FixForwardError
		if errors.As(err, &ffe) {
			_ = ffe.Render(stderr, asJSON, showWhy)
			if ffe.ExitCode != 0 {
				return ffe.ExitCode
			}
			return 1
		}
		fallback := &ux.FixForwardError{
			Tool:           "fabrial",
			Code:           "FABRIAL_INIT_HOOKS_FAILED",
			Summary:        err.Error(),
			RemediationCmd: "fabrial init --hooks --why",
			WhyOneLiner:    "Verify target IDE config permissions and ensure no symlinks exist on the hook config path.",
			ExitCode:       1,
		}
		_ = fallback.Render(stderr, asJSON, showWhy)
		return 1
	}

	if err := report.Render(stdout, asJSON, showWhy); err != nil {
		_, _ = fmt.Fprintf(stderr, "fabrial: failed to render init --hooks output: %v\n", err)
		return 1
	}
	return 0
}
