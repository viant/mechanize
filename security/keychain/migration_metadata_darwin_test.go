//go:build darwin && cgo

package keychain

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// These paths reject before any Keychain lookup. No test supplies an existing
// correctly pinned broker to the native metadata adapter.
func TestMigrationMetadataRejectsUntrustedContextWithoutKeychain(t *testing.T) {
	reader := nativeMigrationMetadata{}
	options := migrationFixtureOptions()
	if _, err := reader.prepare(context.Background(), options); !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("untrusted preparation admitted")
	}
	if err := reader.verifyBeforeCommit(context.Background(), options, nil); !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("untrusted verification admitted")
	}
	if _, err := reader.inspect(context.Background(), options, []byte("fixture-reference")); !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("untrusted inspection admitted")
	}
}
func TestMigrationMetadataMissingCanonicalCodeRejectsBeforeKeychainLookup(t *testing.T) {
	reader := nativeMigrationMetadata{}
	options := migrationFixtureOptions()
	options.canonicalExecutable = filepath.Join(t.TempDir(), "absent-canonical-broker")
	ctx := migrationFixtureContext(t, true)
	if prepared, err := reader.prepare(ctx, options); prepared != nil || !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("missing code admitted preparation")
	}
	if result, err := reader.inspect(ctx, options, []byte("fixture-reference")); result.exactNewPolicy || !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("missing code admitted inspection")
	}
}
func TestMigrationMetadataRejectsUnownedPreparationHandle(t *testing.T) {
	reader := nativeMigrationMetadata{}
	options := migrationFixtureOptions()
	ctx := migrationFixtureContext(t, true)
	foreign := &migrationPrepared{identity: []byte("fixture-reference"), handle: new(int)}
	if err := reader.verifyBeforeCommit(ctx, options, foreign); !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("foreign preparation admitted")
	}
}
