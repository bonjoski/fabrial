package pillars

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/bonjoski/fabrial/pkg/ux"
)

// compiledFixtures caches real compiled Go binaries once per test run so unit and
// adversarial tests exercise authentic Mach-O/ELF debug/buildinfo & SHA-256 verification
// in <200ms total without recompiling per subtest.
var (
	fixtureOnce       sync.Once
	fixtureErr        error
	fixtureRoot       string
	genuineShieldBin  string
	genuineStormBin   string
	evilCollisionBin  string
	forgedShieldBin   string
)

func TestMain(m *testing.M) {
	code := m.Run()
	if fixtureRoot != "" {
		_ = os.RemoveAll(fixtureRoot)
	}
	os.Exit(code)
}

func buildRealGoFixture(outDir, modPath, subPkg, binName, marker string) (string, error) {
	srcDir := filepath.Join(outDir, "src-"+binName+"-"+marker)
	pkgDir := filepath.Join(srcDir, filepath.FromSlash(subPkg))
	if err := os.MkdirAll(pkgDir, 0755); err != nil {
		return "", err
	}
	goMod := "module " + modPath + "\n\ngo 1.24\n"
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte(goMod), 0644); err != nil {
		return "", err
	}
	mainSrc := "package main\nconst marker = \"" + marker + "\"\nfunc main() { _ = marker }\n"
	if err := os.WriteFile(filepath.Join(pkgDir, "main.go"), []byte(mainSrc), 0644); err != nil {
		return "", err
	}

	outBin := filepath.Join(outDir, binName+"-"+marker)
	if runtime.GOOS == "windows" {
		outBin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", outBin, "./"+subPkg)
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", errors.New("go build fixture failed: " + err.Error() + ": " + string(out))
	}
	return outBin, nil
}

func ensureCompiledFixtures(t *testing.T) {
	t.Helper()
	fixtureOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fabrial-pillars-fixtures-*")
		if err != nil {
			fixtureErr = err
			return
		}
		fixtureRoot = dir

		genuineShieldBin, fixtureErr = buildRealGoFixture(dir, "github.com/bonjoski/shield", "cmd/shield", "shield", "genuine")
		if fixtureErr != nil {
			return
		}
		genuineStormBin, fixtureErr = buildRealGoFixture(dir, "github.com/bonjoski/stormcage", "cmd/stormcage", "stormcage", "genuine")
		if fixtureErr != nil {
			return
		}
		evilCollisionBin, fixtureErr = buildRealGoFixture(dir, "github.com/evil/shield", "cmd/shield", "shield", "thirdparty")
		if fixtureErr != nil {
			return
		}
		forgedShieldBin, fixtureErr = buildRealGoFixture(dir, "github.com/bonjoski/shield", "cmd/shield", "shield", "forged-trojan-v2")
	})
	if fixtureErr != nil {
		t.Fatalf("compile Go provenance fixtures: %v", fixtureErr)
	}
}

func installFixtureCopy(t *testing.T, srcBin, dstDir, name string) string {
	t.Helper()
	data, err := os.ReadFile(srcBin)
	if err != nil {
		t.Fatalf("read fixture %s: %v", srcBin, err)
	}
	dst := filepath.Join(dstDir, name)
	if runtime.GOOS == "windows" {
		dst += ".exe"
	}
	if err := os.WriteFile(dst, data, 0755); err != nil {
		t.Fatalf("write fixture %s: %v", dst, err)
	}
	resolved, err := filepath.EvalSymlinks(dst)
	if err == nil {
		return resolved
	}
	return dst
}

func TestResolve_State1_AbsentAndUnrequired(t *testing.T) {
	emptyDir := t.TempDir()
	r := &Resolver{Lookup: LookupInPATH(emptyDir), DisableTrustStore: true}
	req := Requirements{RequireShield: false, RequireStormcage: false}

	shieldRes := r.ResolveShield(req)
	if shieldRes.State != StateAbsent {
		t.Fatalf("expected Shield StateAbsent, got %s", shieldRes.State)
	}
	if shieldRes.IsVisible() || shieldRes.IsActive() {
		t.Fatalf("expected Shield invisible and inactive in State 1, got %+v", shieldRes)
	}
	if shieldRes.Err != nil {
		t.Fatalf("expected nil Err in State 1, got %v", shieldRes.Err)
	}

	scRes := r.ResolveStormcage(req)
	if scRes.State != StateAbsent {
		t.Fatalf("expected Stormcage StateAbsent, got %s", scRes.State)
	}
	if scRes.IsVisible() || scRes.IsActive() {
		t.Fatalf("expected Stormcage invisible and inactive in State 1, got %+v", scRes)
	}

	if err := r.EnforceRequired(req); err != nil {
		t.Fatalf("expected EnforceRequired nil in State 1, got %v", err)
	}
}

func TestResolve_State2_InstalledAutoDiscoveredWithBuildInfo(t *testing.T) {
	ensureCompiledFixtures(t)
	binDir := t.TempDir()
	shieldPath := installFixtureCopy(t, genuineShieldBin, binDir, "shield")
	scPath := installFixtureCopy(t, genuineStormBin, binDir, "stormcage")

	r := &Resolver{Lookup: LookupInPATH(binDir), DisableTrustStore: true}
	req := Requirements{RequireShield: false, RequireStormcage: false}

	shieldRes := r.ResolveShield(req)
	if shieldRes.State != StateInstalled {
		t.Fatalf("expected Shield StateInstalled, got %s (err=%v)", shieldRes.State, shieldRes.Err)
	}
	if !shieldRes.IsVisible() || !shieldRes.IsActive() {
		t.Fatalf("expected Shield visible and active in State 2, got %+v", shieldRes)
	}
	if shieldRes.BinaryPath != shieldPath {
		t.Fatalf("expected canonical BinaryPath=%s, got %s", shieldPath, shieldRes.BinaryPath)
	}
	if shieldRes.ModulePath != "github.com/bonjoski/shield" {
		t.Fatalf("expected ModulePath=github.com/bonjoski/shield, got %q", shieldRes.ModulePath)
	}

	scRes := r.ResolveStormcage(req)
	if scRes.State != StateInstalled {
		t.Fatalf("expected Stormcage StateInstalled, got %s (err=%v)", scRes.State, scRes.Err)
	}
	if scRes.BinaryPath != scPath {
		t.Fatalf("expected canonical BinaryPath=%s, got %s", scPath, scRes.BinaryPath)
	}
	if scRes.ModulePath != "github.com/bonjoski/stormcage" {
		t.Fatalf("expected ModulePath=github.com/bonjoski/stormcage, got %q", scRes.ModulePath)
	}

	if err := r.EnforceRequired(Requirements{RequireShield: true, RequireStormcage: true}); err != nil {
		t.Fatalf("expected EnforceRequired nil when both verified binaries installed, got %v", err)
	}
}

func TestResolve_State2_PartialInstall(t *testing.T) {
	ensureCompiledFixtures(t)
	binDir := t.TempDir()
	installFixtureCopy(t, genuineShieldBin, binDir, "shield")

	r := &Resolver{Lookup: LookupInPATH(binDir), DisableTrustStore: true}
	req := Requirements{}

	if got := r.ResolveShield(req).State; got != StateInstalled {
		t.Fatalf("expected Shield StateInstalled, got %s", got)
	}
	if got := r.ResolveStormcage(req).State; got != StateAbsent {
		t.Fatalf("expected Stormcage StateAbsent, got %s", got)
	}
}

func TestResolve_State3_RequiredMissingFailClosed(t *testing.T) {
	emptyDir := t.TempDir()
	r := &Resolver{Lookup: LookupInPATH(emptyDir), DisableTrustStore: true}

	for _, tc := range []struct {
		name   string
		pillar OptionalPillar
		req    Requirements
		field  string
	}{
		{"ShieldRequiredMissing", Shield, Requirements{RequireShield: true}, "require_shield"},
		{"StormcageRequiredMissing", Stormcage, Requirements{RequireStormcage: true}, "require_stormcage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := r.Resolve(tc.pillar, tc.req)
			if res.State != StateRequiredMissing {
				t.Fatalf("expected StateRequiredMissing, got %s", res.State)
			}
			if !res.IsVisible() || res.IsActive() || !res.Required {
				t.Fatalf("unexpected resolution flags: %+v", res)
			}
			if res.Err == nil {
				t.Fatal("FAIL-OPEN: expected non-nil error in State 3")
			}

			var ffe *ux.FixForwardError
			if !errors.As(res.Err, &ffe) {
				t.Fatalf("expected *ux.FixForwardError, got %T", res.Err)
			}
			if ffe.ExitCode != ExitCodeRequiredMissing {
				t.Fatalf("expected ExitCode %d, got %d", ExitCodeRequiredMissing, ffe.ExitCode)
			}
			if !strings.Contains(ffe.Summary, tc.field) {
				t.Fatalf("expected Summary to mention %s, got %q", tc.field, ffe.Summary)
			}
			if ffe.RemediationCmd == "" || ffe.WhyOneLiner == "" {
				t.Fatalf("expected non-empty RemediationCmd and WhyOneLiner: %+v", ffe)
			}

			enforceErr := r.EnforceRequired(tc.req)
			if enforceErr == nil {
				t.Fatal("FAIL-OPEN: EnforceRequired returned nil in State 3")
			}
		})
	}
}

func TestTrustPillar_RoundTripAndStrictPinning(t *testing.T) {
	ensureCompiledFixtures(t)
	binDir := t.TempDir()
	shieldPath := installFixtureCopy(t, genuineShieldBin, binDir, "shield")
	storePath := filepath.Join(t.TempDir(), ".fabrial", "trusted-pillars.json")

	res, err := TrustPillar("shield", storePath, LookupInPATH(binDir))
	if err != nil {
		t.Fatalf("TrustPillar failed: %v", err)
	}
	if res.BinaryPath != shieldPath {
		t.Fatalf("expected pinned BinaryPath=%s, got %s", shieldPath, res.BinaryPath)
	}
	if !IsValidSHA256Hex(res.SHA256) {
		t.Fatalf("invalid SHA256 returned: %q", res.SHA256)
	}

	r := &Resolver{Lookup: LookupInPATH(binDir), TrustStorePath: storePath}
	resolved := r.ResolveShield(Requirements{RequireShield: true, StrictPillarPinning: true})
	if resolved.State != StateInstalled || resolved.SHA256 != res.SHA256 {
		t.Fatalf("expected StateInstalled with matching SHA256, got %+v", resolved)
	}

	removed, err := RemoveTrustedPillar("shield", storePath)
	if err != nil || !removed {
		t.Fatalf("RemoveTrustedPillar failed: removed=%v err=%v", removed, err)
	}
}

func TestLoadRequirements_FromFabrialYAML(t *testing.T) {
	dir := t.TempDir()

	// Default (no fabrial.yaml): both false
	req, err := LoadRequirements("", dir)
	if err != nil {
		t.Fatalf("LoadRequirements without file failed: %v", err)
	}
	if req.RequireShield || req.RequireStormcage || req.StrictPillarPinning {
		t.Fatalf("expected all requirements false by default, got %+v", req)
	}

	// Explicit fabrial.yaml with require_shield, require_stormcage, strict_pillar_pinning & pillar_digests
	digest := strings.Repeat("a", 64)
	yamlContent := "version: \"1\"\nrequire_shield: true\nrequire_stormcage: true\nstrict_pillar_pinning: true\npillar_digests:\n  shield: \"" + digest + "\"\n"
	yamlPath := filepath.Join(dir, "fabrial.yaml")
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("write fabrial.yaml: %v", err)
	}

	req2, err := LoadRequirements("", dir)
	if err != nil {
		t.Fatalf("LoadRequirements with file failed: %v", err)
	}
	if !req2.RequireShield || !req2.RequireStormcage || !req2.StrictPillarPinning {
		t.Fatalf("expected all requirement flags true, got %+v", req2)
	}
	if req2.PillarDigests["shield"] != digest {
		t.Fatalf("expected pillar_digests.shield=%s, got %q", digest, req2.PillarDigests["shield"])
	}
}
