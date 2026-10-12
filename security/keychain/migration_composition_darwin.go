//go:build darwin && cgo

package keychain

import (
	"context"
	"os"

	"github.com/viant/mechanize/auth/nativepeer"
)

// Usable only in the exact isolated signed worker after authenticated bootstrap.
// Full-runtime staging/readiness hooks remain explicit integration gates; this
// constructor supplies no permissive defaults and adds no packaged dispatch mode.
func newSignedMigrationComposition(ctx context.Context, authority *migrationNativeAuthority, enrollment migrationCompositionEnrollment,
	quiescent, runtimePrepared func(context.Context) error, runtimeReady, keyReady func(context.Context, migrationStagePlan) error) (*migrationComposition, error) {
	if authority == nil || !nativeMigrationExecutorMatches(enrollment.worker.executorRequirement) {
		return nil, errMigrationUnavailable
	}
	acl, err := newFileMigrationJournal(enrollment.aclJournalRoot)
	if err != nil {
		return nil, errMigrationUnavailable
	}
	stage, err := newRuntimeStageJournal(enrollment.stageJournalRoot)
	if err != nil {
		return nil, errMigrationUnavailable
	}
	approval, err := newMigrationApprovalTransport(authority, enrollment.worker, acl)
	if err != nil {
		return nil, errMigrationUnavailable
	}
	self := func(ctx context.Context) error {
		if migrationContext(ctx) != nil || !nativeMigrationExecutorMatches(enrollment.worker.executorRequirement) {
			return errMigrationUnavailable
		}
		return nil
	}
	code := func(ctx context.Context, path, requirement string) error {
		if enrollment.unified != nil && (requirement == enrollment.unified.NewRequirement || requirement == enrollment.unified.OldRequirement) {
			return (nativeRuntimeSignatureVerifier{}).verify(ctx, "console", path, requirement)
		}
		if migrationContext(ctx) != nil || !migrationRequirement.MatchString(requirement) {
			return errMigrationUnavailable
		}
		unchanged, release, err := migrationExecutableCustody(path)
		if err != nil {
			return errMigrationUnavailable
		}
		defer release()
		if nativepeer.VerifyExecutable(path, nativepeer.Options{ExpectedUID: uint32(os.Getuid()), DesignatedRequirement: requirement}) != nil || !unchanged() || migrationContext(ctx) != nil {
			return errMigrationUnavailable
		}
		return nil
	}
	gates := migrationCompositionGates{self: self, code: code, quiescent: quiescent, runtimePrepared: runtimePrepared, runtimeReady: runtimeReady, keyReady: keyReady}
	return newMigrationCompositionWith(ctx, authority.workerAuthority, enrollment, nativeMigrationMetadata{}, acl, stage, approval.approve, gates)
}
