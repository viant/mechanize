//go:build darwin && cgo

package keychain

/*
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
int mechanize_master_inspect(const char *, const char *, const char *, CFDataRef *);
int mechanize_master_read(const char *, const char *, const char *, const void *, int, CFDataRef *);
int mechanize_master_add(const char *, const char *, const char *, const void *, int, CFDataRef *);
int mechanize_master_refresh_access(const char *, const char *, const char *, const void *, int, CFDataRef *);
*/
import "C"

import (
	"context"
	"github.com/viant/mechanize/auth"
	"unsafe"
)

type nativeMasterStore struct{ options MasterKeyOptions }

func newMasterKeyStore(options MasterKeyOptions) (masterKeyStore, error) {
	return &nativeMasterStore{options: options}, nil
}
func (s *nativeMasterStore) call(ctx context.Context, operation string, input []byte) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ErrMasterKeyUnavailable
	}
	service, account, requirement := C.CString(s.options.Item.Service), C.CString(s.options.Item.Account), C.CString(s.options.BrokerRequirement)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	defer C.free(unsafe.Pointer(requirement))
	var result C.CFDataRef
	var status C.int
	switch operation {
	case "inspect":
		status = C.mechanize_master_inspect(service, account, requirement, &result)
	case "read":
		if !validMasterIdentity(input) {
			return nil, ErrMasterKeyUnavailable
		}
		status = C.mechanize_master_read(service, account, requirement, unsafe.Pointer(&input[0]), C.int(len(input)), &result)
	case "add":
		if len(input) == 0 || len(input) > 256 {
			return nil, ErrMasterKeyUnavailable
		}
		status = C.mechanize_master_add(service, account, requirement, unsafe.Pointer(&input[0]), C.int(len(input)), &result)
	case "refreshAccess":
		if !auth.NativeHuman(ctx) || !validMasterIdentity(input) {
			return nil, ErrMasterKeyUnavailable
		}
		status = C.mechanize_master_refresh_access(service, account, requirement, unsafe.Pointer(&input[0]), C.int(len(input)), &result)
	default:
		return nil, ErrMasterKeyUnavailable
	}
	if result != 0 {
		defer C.CFRelease(C.CFTypeRef(result))
	}
	if status != 0 || ctx.Err() != nil {
		return nil, ErrMasterKeyUnavailable
	}
	if result == 0 && operation == "inspect" {
		return nil, nil
	}
	if result == 0 {
		return nil, ErrMasterKeyUnavailable
	}
	size := C.CFDataGetLength(result)
	limit := C.CFIndex(16384)
	if operation == "read" {
		limit = 256
	}
	if size <= 0 || size > limit {
		return nil, ErrMasterKeyUnavailable
	}
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(result)), C.int(size)), nil
}
func (s *nativeMasterStore) refreshAccess(ctx context.Context, identity []byte) ([]byte, error) {
	return s.call(ctx, "refreshAccess", identity)
}
func (s *nativeMasterStore) inspect(ctx context.Context) ([]byte, error) {
	return s.call(ctx, "inspect", nil)
}
func (s *nativeMasterStore) read(ctx context.Context, identity []byte) ([]byte, error) {
	return s.call(ctx, "read", identity)
}
func (s *nativeMasterStore) add(ctx context.Context, material []byte) ([]byte, error) {
	return s.call(ctx, "add", material)
}
