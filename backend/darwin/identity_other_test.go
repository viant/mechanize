//go:build !darwin || !cgo

package darwin

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth/nativepeer"
	"os"
	"testing"
)

func TestSignedHelperTrustUnavailableFailsClosed(t *testing.T) {
	uid := uint32(os.Getuid())
	client, err := NewClient(context.Background(), Options{HelperPath: "/must-not-launch", Requirement: `identifier "fixture"`, ExpectedUID: &uid})
	if client != nil || !errors.Is(err, nativepeer.ErrUnsupported) {
		t.Fatalf("client=%v error=%v", client, err)
	}
}
