//go:build darwin || linux

package keychain

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func proxyFixture(t *testing.T, mode string) (*migrationProcessBackend, context.Context) {
	t.Helper()
	launch := func(ctx context.Context, options migrationOptions, identity []byte) (*migrationChildProcess, error) {
		if options != migrationFixtureOptions() {
			return nil, errMigrationUnavailable
		}
		if identity != nil && !bytes.Equal(identity, []byte("public-fixture-reference")) {
			return nil, errMigrationUnavailable
		}
		child, _ := migrationProcessFixture(t, mode)
		return child, nil
	}
	backend, err := newMigrationProcessBackend(migrationFixtureOptions(), launch)
	if err != nil {
		t.Fatal(err)
	}
	return backend, migrationFixtureContext(t, true)
}
func TestMigrationProxyLinksCoordinatorWithoutKeychain(t *testing.T) {
	backend, ctx := proxyFixture(t, "echo")
	_, _, journal, _ := migrationFixture(t)
	approval := func(ctx context.Context, transition migrationTransition) (migrationApproval, error) {
		return migrationApproval{approved: true, binding: transition.Binding}, nil
	}
	coordinator, err := newMigrationCoordinator(migrationFixtureOptions(), backend, journal, approval)
	if err != nil {
		t.Fatal(err)
	}
	prepareMigrationFixture(t, coordinator, ctx)
	receipt, err := coordinator.commit(ctx)
	if err != nil || receipt.State != migrationVerified || journal.record == nil || journal.record.state != migrationVerified {
		t.Fatal("private proxy did not preserve ordered verification")
	}
	if _, err = coordinator.commit(ctx); !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("verified transaction replayed")
	}
}
func TestMigrationProxyTimeoutPreservesJournalAndCannotReplay(t *testing.T) {
	backend, ctx := proxyFixture(t, "hang")
	_, _, journal, _ := migrationFixture(t)
	approval := func(ctx context.Context, transition migrationTransition) (migrationApproval, error) {
		return migrationApproval{approved: true, binding: transition.Binding}, nil
	}
	coordinator, err := newMigrationCoordinator(migrationFixtureOptions(), backend, journal, approval)
	if err != nil {
		t.Fatal(err)
	}
	prepareMigrationFixture(t, coordinator, ctx)
	bounded, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	receipt, err := coordinator.commit(bounded)
	if !errors.Is(err, errMigrationUnknown) || receipt.State != migrationUnknown || journal.record == nil || journal.record.state != migrationUnknown {
		t.Fatal("stalled proxy commit lost durable uncertainty")
	}
	if _, err = coordinator.commit(ctx); !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("unknown proxy commit replayed")
	}
}
func TestMigrationProxyRefusesForeignHandleOptionsAndUntrustedContext(t *testing.T) {
	backend, ctx := proxyFixture(t, "echo")
	if _, err := backend.prepare(context.Background(), migrationFixtureOptions()); !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("untrusted proxy preparation admitted")
	}
	options := migrationFixtureOptions()
	options.alias = "other"
	if _, err := backend.prepare(ctx, options); !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("foreign enrollment admitted")
	}
	if err := backend.commit(ctx, migrationFixtureOptions(), &migrationPrepared{identity: []byte("public-ref"), handle: new(int)}); !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("foreign handle committed")
	}
}
