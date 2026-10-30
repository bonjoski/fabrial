package version

import (
	"testing"
)

func TestVersion_Format(t *testing.T) {
	if Version == "" {
		t.Fatalf("expected non-empty Version")
	}
	if Version != "0.5.0" {
		t.Logf("built version: %s", Version)
	}
}
