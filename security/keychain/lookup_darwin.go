//go:build darwin && cgo

package keychain

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -framework Foundation -framework LocalAuthentication
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
OSStatus mechanize_keychain_lookup(const char *service, const char *account, CFDataRef *result);
*/
import "C"

import (
	"context"
	"fmt"
	"unsafe"
)

func supported() error { return nil }
func lookup(ctx context.Context, item Item) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	service, account := C.CString(item.Service), C.CString(item.Account)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	var data C.CFDataRef
	status := C.mechanize_keychain_lookup(service, account, &data)
	if status != 0 {
		return nil, fmt.Errorf("Keychain lookup denied or unavailable (Security status %d)", int(status))
	}
	defer C.CFRelease(C.CFTypeRef(data))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	length := C.CFDataGetLength(data)
	if length < 0 || length > 16*1024*1024 {
		return nil, fmt.Errorf("Keychain item exceeds supported size")
	}
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(data)), C.int(length)), nil
}
