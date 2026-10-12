//go:build darwin && cgo

package keychain

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// No valid migration-helper identity is provided. These tests cannot pass the
// first native self-role gate and never query or change a Keychain item.
func TestMigrationWriterRejectsOrdinaryProcessAndBroadenedIdentity(t *testing.T) {
	for _, rule := range []string{
		"", migrationFixtureOptions().newRequirement,
		`identifier "com.viant.mechanize.custody-migration"`,
		`identifier "com.viant.mechanize.custody-migration" and cdhash H"` + strings.Repeat("0", 40) + `"`,
		`identifier "com.viant.mechanize.custody-migration" and cdhash H"` + strings.Repeat("0", 40) + `" or true`,
	} {
		if nativeMigrationExecutorMatches(rule) {
			t.Fatal("unqualified executable admitted as migration helper")
		}
	}
}
func TestMigrationWriterCannotBeInvokedByOrdinaryNativeHumanProcess(t *testing.T) {
	ctx := migrationFixtureContext(t, true)
	rule := `identifier "com.viant.mechanize.custody-migration" and cdhash H"` + strings.Repeat("0", 40) + `"`
	prepared := &migrationPrepared{identity: []byte("public-fixture-reference"), handle: new(int)}
	if err := (nativeMigrationMetadata{}).commitAsIsolatedHelper(ctx, migrationFixtureOptions(), prepared, rule); !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("ordinary process admitted write")
	}
	if err := (nativeMigrationMetadata{}).commitAsIsolatedHelper(context.Background(), migrationFixtureOptions(), prepared, rule); !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("untrusted context admitted write")
	}
}
