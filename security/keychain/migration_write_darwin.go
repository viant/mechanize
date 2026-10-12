//go:build darwin && cgo

package keychain

/*
#include <Security/Security.h>
typedef struct MechanizeMigrationMetadata MechanizeMigrationMetadata;
int mechanize_migration_executor_matches(const char *);
int mechanize_migration_write(MechanizeMigrationMetadata *, const char *, const char *, const char *, const char *, const char *);
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"regexp"
	"unsafe"
)

var migrationExecutorRequirement = regexp.MustCompile(`^identifier "com\.viant\.mechanize\.custody-migration" and cdhash H"[a-f0-9]{40}"$`)

// Probe only the current executable's public signing identity. No Keychain API
// or platform authorization UI is called by this gate.
func nativeMigrationExecutorMatches(requirement string) bool {
	if !migrationExecutorRequirement.MatchString(requirement) {
		return false
	}
	value := C.CString(requirement)
	defer C.free(unsafe.Pointer(value))
	return C.mechanize_migration_executor_matches(value) == 1
}

// Unwired primitive for a separately enrolled, isolated helper process only.
// It deliberately is NOT migrationBackend.commit: an authenticated parent,
// immutable bound local approval and a watchdog/closed child protocol are still
// required. Ordinary broker code cannot satisfy the distinct exact self pin.
// The caller must have durably recorded uncertainty before entering this method.
func (nativeMigrationMetadata) commitAsIsolatedHelper(ctx context.Context, options migrationOptions, prepared *migrationPrepared, executorRequirement string) error {
	if migrationContext(ctx) != nil || !validMigrationOptions(options) || !nativeMigrationExecutorMatches(executorRequirement) || prepared == nil || !validMasterIdentity(prepared.identity) {
		return errMigrationUnavailable
	}
	handle, ok := prepared.handle.(*nativeMigrationMetadataHandle)
	if !ok || handle == nil || handle.options != options {
		return errMigrationUnavailable
	}
	if err := (nativeMigrationMetadata{}).verifyBeforeCommit(ctx, options, prepared); err != nil {
		return errMigrationUnavailable
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.pointer == nil || migrationContext(ctx) != nil {
		return errMigrationUnavailable
	}
	path, rule, service, account, cleanup := migrationNativeStrings(options, options.newRequirement)
	defer cleanup()
	executor := C.CString(executorRequirement)
	defer C.free(unsafe.Pointer(executor))
	status := C.mechanize_migration_write(handle.pointer, path, rule, service, account, executor)
	if status == 1 && migrationContext(ctx) == nil {
		return nil
	}
	if status == 0 && migrationContext(ctx) == nil {
		return errMigrationUnavailable
	}
	return errMigrationUnknown
}
