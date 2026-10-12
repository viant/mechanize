//go:build darwin && cgo

package keychain

import (
	"context"
	"io"
	"net"

	"github.com/viant/mechanize/auth"
)

func serveMigrationPreparationEntry(ctx context.Context, channel io.ReadWriteCloser, console *net.UnixConn, enrollment migrationEntryEnrollment, frozen migrationPackagedEnrollment, verifier *auth.Verifier) error {
	if frozen.Preparation == nil || !frozen.Preparation.valid() || enrollment.worker.expectedIdentity != nil {
		return errMigrationUnavailable
	}
	authority, err := newMigrationNativeAuthority(console, enrollment.parent, verifier)
	if err != nil {
		return errMigrationUnavailable
	}
	defer authority.close()
	loader, err := newMigrationBootstrapLoader(enrollment.worker, enrollment.configDigest, enrollment.parent.parentRequirement, authority.authenticate)
	if err != nil {
		return errMigrationUnavailable
	}
	config, err := loader.load(ctx, channel)
	if err != nil {
		return errMigrationUnavailable
	}
	runtime := migrationPreparationRuntime{authority: authority.workerAuthority, metadata: nativeMigrationMetadata{}.prepare,
		frozen: func(ctx context.Context) error {
			if migrationContext(ctx) != nil {
				return errMigrationUnavailable
			}
			raw, e := readMigrationPackagedResource(frozen.Config)
			if e != nil {
				return errMigrationUnavailable
			}
			defer func() {
				for i := range raw {
					raw[i] = 0
				}
			}()
			if !migrationEnrollmentMatchesConfiguration(frozen, raw) {
				return errMigrationUnavailable
			}
			return nil
		}, acquire: func(ctx context.Context) (func() error, func(), error) {
			if migrationContext(ctx) != nil {
				return nil, nil, errMigrationUnavailable
			}
			if frozen.Version == 3 {
				return migrationPlacementLock(frozen.Config.Path)
			}
			return migrationPlacementLock(config.options.canonicalExecutable)
		}}
	return serveMigrationPreparation(ctx, channel, config, enrollment.configDigest, *frozen.Preparation, runtime)
}
