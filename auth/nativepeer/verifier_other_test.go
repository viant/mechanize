//go:build !darwin || !cgo

package nativepeer

import (
	"errors"
	"testing"
)

func TestUnsupported(t *testing.T) {
	if verify, err := NewVerifier(Options{DesignatedRequirement: `identifier "fixture"`}); verify != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported platform: %v", err)
	}
}
