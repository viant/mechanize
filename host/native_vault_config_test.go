package host

import (
	"context"
	"github.com/viant/mechanize/vault"
	"strings"
	"testing"
)

func TestNativeVaultProviderRequiresEnrolledConsoleBeforeInitialization(t *testing.T) {
	h, err := NewWithOptions(context.Background(), Config{}, HostOptions{NativeVaultInput: &vault.NativeInputService{}})
	if h != nil || err == nil || !strings.Contains(err.Error(), "enrolled signed console") {
		t.Fatal("Vault provider accepted without native channel")
	}
}
