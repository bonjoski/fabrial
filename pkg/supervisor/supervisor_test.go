package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestSupervisor_DefaultServicesDefined(t *testing.T) {
	sup := NewDefaultSupervisor()
	if len(sup.Services) != 5 {
		t.Fatalf("expected 5 default daemons, got %d", len(sup.Services))
	}

	names := []string{"Locksmith", "Argus", "Aegisbox", "Shield", "Stormcage"}
	for i, name := range names {
		if sup.Services[i].Name != name {
			t.Errorf("at index %d: expected %s, got %s", i, name, sup.Services[i].Name)
		}
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
