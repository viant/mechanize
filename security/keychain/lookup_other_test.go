//go:build !darwin || !cgo

package keychain

import (
	"context"
	"errors"
	"testing"
)

func TestUnsupported(t *testing.T) {
	if err := Register(Options{}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := lookup(context.Background(), Item{}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}
