//go:build darwin && cgo

package keychain

/*
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
typedef struct MechanizeMigrationMetadata MechanizeMigrationMetadata;
MechanizeMigrationMetadata *mechanize_migration_metadata_prepare(const char *, const char *, const char *, const char *);
void mechanize_migration_metadata_destroy(MechanizeMigrationMetadata *);
int mechanize_migration_metadata_identity(MechanizeMigrationMetadata *, CFDataRef *);
int mechanize_migration_metadata_verify(MechanizeMigrationMetadata *, const char *, const char *, const char *, const char *);
int mechanize_migration_metadata_inspect(const char *, const char *, const char *, const char *, const void *, int);
*/
import "C"

import (
	"bytes"
	"context"
	"sync"
	"unsafe"
)

// Metadata preparation only: deliberately does not implement migrationBackend's
// commit method. There is no production constructor or migration endpoint.
// Framework IPC cannot be forcibly interrupted by a Go context. A separately
// bounded native execution process remains a prerequisite for live integration.
type nativeMigrationMetadata struct{}
type nativeMigrationMetadataHandle struct {
	mu      sync.Mutex
	pointer *C.MechanizeMigrationMetadata
	options migrationOptions
}

func (h *nativeMigrationMetadataHandle) destroy() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pointer != nil {
		C.mechanize_migration_metadata_destroy(h.pointer)
		h.pointer = nil
	}
}
func migrationNativeStrings(o migrationOptions, rule string) (path, requirement, service, account *C.char, cleanup func()) {
	executable := o.canonicalExecutable
	if rule == o.newRequirement {
		executable = o.destinationExecutable()
	}
	path, requirement, service, account = C.CString(executable), C.CString(rule), C.CString(o.item.Service), C.CString(o.item.Account)
	cleanup = func() {
		C.free(unsafe.Pointer(path))
		C.free(unsafe.Pointer(requirement))
		C.free(unsafe.Pointer(service))
		C.free(unsafe.Pointer(account))
	}
	return
}
func (nativeMigrationMetadata) prepare(ctx context.Context, options migrationOptions) (*migrationPrepared, error) {
	if migrationContext(ctx) != nil || !validMigrationOptions(options) {
		return nil, errMigrationUnavailable
	}
	path, rule, service, account, cleanup := migrationNativeStrings(options, options.oldRequirement)
	defer cleanup()
	pointer := C.mechanize_migration_metadata_prepare(path, rule, service, account)
	if pointer == nil {
		return nil, errMigrationUnavailable
	}
	handle := &nativeMigrationMetadataHandle{pointer: pointer, options: options}
	var identity C.CFDataRef
	if C.mechanize_migration_metadata_identity(pointer, &identity) == 0 || identity == 0 {
		handle.destroy()
		return nil, errMigrationUnavailable
	}
	defer C.CFRelease(C.CFTypeRef(identity))
	length := C.CFDataGetLength(identity)
	if length <= 0 || length > 16384 || migrationContext(ctx) != nil {
		handle.destroy()
		return nil, errMigrationUnavailable
	}
	result := &migrationPrepared{identity: C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(identity)), C.int(length)), handle: handle, dispose: handle.destroy}
	return result, nil
}
func (nativeMigrationMetadata) verifyBeforeCommit(ctx context.Context, options migrationOptions, prepared *migrationPrepared) error {
	if migrationContext(ctx) != nil || !validMigrationOptions(options) || prepared == nil || !validMasterIdentity(prepared.identity) {
		return errMigrationUnavailable
	}
	handle, ok := prepared.handle.(*nativeMigrationMetadataHandle)
	if !ok || handle == nil || handle.options != options {
		return errMigrationUnavailable
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.pointer == nil {
		return errMigrationUnavailable
	}
	var identity C.CFDataRef
	if C.mechanize_migration_metadata_identity(handle.pointer, &identity) == 0 || identity == 0 {
		return errMigrationUnavailable
	}
	defer C.CFRelease(C.CFTypeRef(identity))
	length := C.CFDataGetLength(identity)
	if length <= 0 || length > 16384 || !bytes.Equal(prepared.identity, C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(identity)), C.int(length))) {
		return errMigrationUnavailable
	}
	path, rule, service, account, cleanup := migrationNativeStrings(options, options.newRequirement)
	defer cleanup()
	if migrationContext(ctx) != nil || C.mechanize_migration_metadata_verify(handle.pointer, path, rule, service, account) == 0 || migrationContext(ctx) != nil {
		return errMigrationUnavailable
	}
	return nil
}
func (nativeMigrationMetadata) inspect(ctx context.Context, options migrationOptions, identity []byte) (migrationInspection, error) {
	if migrationContext(ctx) != nil || !validMigrationOptions(options) || !validMasterIdentity(identity) {
		return migrationInspection{}, errMigrationUnavailable
	}
	path, rule, service, account, cleanup := migrationNativeStrings(options, options.newRequirement)
	defer cleanup()
	if C.mechanize_migration_metadata_inspect(path, rule, service, account, unsafe.Pointer(&identity[0]), C.int(len(identity))) == 0 || migrationContext(ctx) != nil {
		return migrationInspection{}, errMigrationUnavailable
	}
	return migrationInspection{identity: bytes.Clone(identity), exactNewPolicy: true}, nil
}
