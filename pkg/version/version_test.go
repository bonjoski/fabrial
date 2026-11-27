package version

import (
	"testing"
)

func TestVersion_Format(t *testing.T) {
	if Version == "" {
		t.Fatalf("expected non-empty Version")
	}
	if Version != "0.7.5" {
		t.Fatalf("expected Version 0.7.5, got %s", Version)
	}
}
