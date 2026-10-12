//go:build darwin && cgo

package keychain

import (
	"context"
	"io"
	"net"

	"github.com/viant/mechanize/auth"
)

// These values belong to the reviewed launcher enrollment, not argv or decoded
// bootstrap fields. A packaged command must obtain this exact frozen enrollment
// from its authenticated installation, and verify its own writer code role.
type migrationEntryEnrollment struct {
	journalRoot  string
	worker       migrationWorkerConfig
	configDigest string
	parent       migrationNativeEnrollment
}

// Compose the real native metadata/writer backend with the authenticated console
// channel and closed bootstrap/operation frames. No authority is inferred from
// stdin or NativeHuman claims; administrator bytes use the separate binary channel.
// Approval still requires a separately enrolled local attestation of this exact
// operation and synced unknown journal, never a caller JSON boolean.
func serveMigrationEntry(ctx context.Context, channel io.ReadWriteCloser, console *net.UnixConn,
	enrollment migrationEntryEnrollment, verifier *auth.Verifier, approval migrationWorkerApproval) error {
	if ctx == nil || channel == nil || console == nil || !validMigrationBootstrap(enrollment.worker, enrollment.configDigest) {
		if channel != nil {
			_ = channel.Close()
		}
		if console != nil {
			_ = console.Close()
		}
		return errMigrationUnavailable
	}
	authority, err := newMigrationNativeAuthority(console, enrollment.parent, verifier)
	if err != nil {
		_ = channel.Close()
		_ = console.Close()
		return errMigrationUnavailable
	}
	defer authority.close()
	loader, err := newMigrationBootstrapLoader(enrollment.worker, enrollment.configDigest, enrollment.parent.parentRequirement, authority.authenticate)
	if err != nil {
		_ = channel.Close()
		return errMigrationUnavailable
	}
	config, err := loader.load(ctx, channel)
	if err != nil {
		return errMigrationUnavailable
	}
	if approval == nil {
		if config.expectedIdentity != nil {
			// Restart reconciliation cannot enter prepare/commit.
			approval = func(context.Context, migrationWorkerApprovalBinding) error { return errMigrationUnavailable }
		} else {
			journal, e := newFileMigrationJournal(enrollment.journalRoot)
			if e != nil {
				channel.Close()
				return errMigrationUnavailable
			}
			transport, e := newMigrationApprovalTransport(authority, config, journal)
			if e != nil {
				channel.Close()
				return errMigrationUnavailable
			}
			approval = transport.approve
		}
	}
	worker, err := newMigrationWorker(config, nativeMigrationMetadata{}, authority.workerAuthority, approval)
	if err != nil {
		_ = channel.Close()
		return errMigrationUnavailable
	}
	return worker.serve(ctx, channel)
}
