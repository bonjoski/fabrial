package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bonjoski/fabrial/pkg/pillars"
)

func handleTrust(args []string) {
	os.Exit(runTrust(args, pillars.DefaultTrustStorePath(), pillars.DefaultResolver().Lookup, os.Stdout, os.Stderr))
}

func runTrust(args []string, storePath string, lookup pillars.LookupFunc, stdout, stderr io.Writer) int {
	asJSON := false
	filtered := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--json" {
			asJSON = true
			continue
		}
		filtered = append(filtered, a)
	}

	if len(filtered) == 0 || filtered[0] == "list" {
		ts, names, err := pillars.ListTrustedPillars(storePath)
		if err != nil {
			fmt.Fprintf(stderr, "fabrial trust: %v\n", err)
			return 1
		}
		if asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(ts)
			return 0
		}
		if len(names) == 0 {
			fmt.Fprintln(stdout, "No pillar SHA-256 digests pinned yet. Run: fabrial trust pillar <halfshard|stormcage|...>")
			return 0
		}
		fmt.Fprintf(stdout, "Trusted pillar SHA-256 pins (%s):\n", storePath)
		for _, n := range names {
			fmt.Fprintf(stdout, "  • %-12s sha256:%s\n", n, ts.Digests[n])
		}
		return 0
	}

	switch strings.ToLower(filtered[0]) {
	case "pillar", "pin", "add":
		if len(filtered) < 2 {
			fmt.Fprintln(stderr, "Usage: fabrial trust pillar <name> [--json]")
			return 1
		}
		res, err := pillars.TrustPillar(filtered[1], storePath, lookup)
		if err != nil {
			fmt.Fprintf(stderr, "fabrial trust pillar: %v\n", err)
			return 1
		}
		if asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(res)
			return 0
		}
		fmt.Fprintf(stdout, "✅ Pinned %s (%s)\n", res.Name, res.BinaryPath)
		fmt.Fprintf(stdout, "   Module: %s\n", res.ModulePath)
		fmt.Fprintf(stdout, "   SHA256: %s\n", res.SHA256)
		fmt.Fprintf(stdout, "   Store:  %s\n", res.StorePath)
		return 0

	case "remove", "rm", "unpin":
		if len(filtered) < 2 {
			fmt.Fprintln(stderr, "Usage: fabrial trust remove <name>")
			return 1
		}
		removed, err := pillars.RemoveTrustedPillar(filtered[1], storePath)
		if err != nil {
			fmt.Fprintf(stderr, "fabrial trust remove: %v\n", err)
			return 1
		}
		if !removed {
			fmt.Fprintf(stdout, "No pin found for %s.\n", filtered[1])
			return 0
		}
		fmt.Fprintf(stdout, "Removed SHA-256 pin for %s.\n", filtered[1])
		return 0

	default:
		fmt.Fprintln(stderr, "Usage: fabrial trust [pillar <name> | list | remove <name>] [--json]")
		return 1
	}
}
