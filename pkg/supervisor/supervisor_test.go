package supervisor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/bonjoski/fabrial/pkg/pillars"
	"github.com/bonjoski/fabrial/pkg/ux"
)

func createFakeDaemonBin(t *testing.T, dir, name string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		p += ".exe"
	}
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write fake binary %s: %v", name, err)
	}
}

func TestSupervisor_DefaultServicesDefined(t *testing.T) {
	// State 1: Neither Shield nor Stormcage installed & unrequired -> only 3 core daemons
	emptyBin := t.TempDir()
	supState1 := NewSupervisor(&pillars.Resolver{Lookup: pillars.LookupInPATH(emptyBin)}, pillars.Requirements{})
	if len(supState1.Services) != 3 {
		t.Fatalf("State 1: expected 3 core daemons, got %d", len(supState1.Services))
	}
	coreNames := []string{"Locksmith", "Argus", "Aegisbox"}
	for i, name := range coreNames {
		if supState1.Services[i].Name != name {
			t.Errorf("State 1 at index %d: expected %s, got %s", i, name, supState1.Services[i].Name)
		}
	}
	if _, ok := supState1.GetService("Shield"); ok {
		t.Fatalf("State 1: Shield service must not be registered when absent & unrequired")
	}
	if _, ok := supState1.GetService("Stormcage"); ok {
		t.Fatalf("State 1: Stormcage service must not be registered when absent & unrequired")
	}

	// State 2: Both Shield and Stormcage installed -> all 5 daemons registered
	supState2 := NewSupervisor(&pillars.Resolver{
		Lookup: pillars.StaticLookup(map[string]string{
			"shield":    "/opt/homebrew/Cellar/shield/0.4.0/bin/shield",
			"stormcage": "/opt/homebrew/Cellar/stormcage/0.4.0/bin/stormcage",
		}),
		DisableTrustStore: true,
	}, pillars.Requirements{})
	if len(supState2.Services) != 5 {
		t.Fatalf("State 2: expected 5 daemons, got %d", len(supState2.Services))
	}
	allNames := []string{"Locksmith", "Argus", "Aegisbox", "Shield", "Stormcage"}
	for i, name := range allNames {
		if supState2.Services[i].Name != name {
			t.Errorf("State 2 at index %d: expected %s, got %s", i, name, supState2.Services[i].Name)
		}
	}

	// State 3: require_shield: true with missing binary -> Shield registered as Required and Start fails closed (exit 126)
	supState3 := NewSupervisor(&pillars.Resolver{Lookup: pillars.LookupInPATH(emptyBin)}, pillars.Requirements{RequireShield: true})
	def, ok := supState3.GetService("Shield")
	if !ok || !def.Required {
		t.Fatalf("State 3: expected Shield registered with Required=true, got ok=%v def=%+v", ok, def)
	}
	err := supState3.Start(context.Background(), "Shield")
	if err == nil {
		t.Fatal("FAIL-OPEN: expected Start(Shield) to fail closed in State 3")
	}
	var ffe *ux.FixForwardError
	if !errors.As(err, &ffe) || ffe.ExitCode != pillars.ExitCodeRequiredMissing {
		t.Fatalf("State 3: expected FixForwardError exit 126, got %v", err)
	}
}

func TestSupervisor_StopService_CleansPIDAndSocket(t *testing.T) {
	tempDir := t.TempDir()
	pidFile := filepath.Join(tempDir, "test.pid")
	sockFile := filepath.Join(tempDir, "test.sock")

	// Write mock dead PID
	_ = os.WriteFile(pidFile, []byte(strconv.Itoa(999999)), 0600)
	_ = os.WriteFile(sockFile, []byte("mock"), 0600)

	sup := &Supervisor{}
	def := ServiceDef{
		Name:       "MockService",
		BinaryName: "mock",
		PIDFile:    pidFile,
		SocketPath: sockFile,
	}

	res := sup.StopService(context.Background(), def)
	if res.State != StateStopped {
		t.Errorf("expected StateStopped, got %v", res.State)
	}

	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Errorf("expected PID file to be removed after stop")
	}
	if _, err := os.Stat(sockFile); !os.IsNotExist(err) {
		t.Errorf("expected socket file to be removed after stop")
	}
}

func TestSupervisor_QueryStatus_ReportsOfflineWhenInactive(t *testing.T) {
	sup := &Supervisor{}
	def := ServiceDef{
		Name: "MockInactive",
		HealthProbe: func(_ context.Context) bool {
			return false
		},
	}

	st := sup.QueryStatus(context.Background(), def)
	if st.State != StateStopped {
		t.Errorf("expected StateStopped for inactive service, got %v", st.State)
	}
}

func TestSupervisor_QueryStatus_ReportsRunningWhenHealthy(t *testing.T) {
	sup := &Supervisor{}
	def := ServiceDef{
		Name: "MockActive",
		HealthProbe: func(_ context.Context) bool {
			return true
		},
	}

	st := sup.QueryStatus(context.Background(), def)
	if st.State != StateRunning {
		t.Errorf("expected StateRunning for healthy service, got %v", st.State)
	}
}
