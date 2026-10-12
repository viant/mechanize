//go:build darwin && cgo

package vault

/*
#cgo LDFLAGS: -framework AppKit -framework ApplicationServices -framework Security -framework Foundation
#include <stdlib.h>
int mechanize_vault_console_windows(unsigned int uid, const char *requirement, const char *prefix, const char *expectedTitle, int *consoles, int *protectedWindow, int *matched);
*/
import "C"

import (
	"context"
	"unsafe"
)

func newNativeWindowProbe(options NativeWindowOptions) (nativeWindowProbe, error) {
	return func(ctx context.Context, entryID string) (nativeWindowState, error) {
		if ctx.Err() != nil {
			return nativeWindowState{}, nativeProbeFailure(nativeProbeContextExpired)
		}
		requirement, prefix := C.CString(options.ConsoleRequirement), C.CString(SecureEntryWindowTitlePrefix)
		defer C.free(unsafe.Pointer(requirement))
		defer C.free(unsafe.Pointer(prefix))
		if entryID != "" && !nativeRevision(entryID) {
			return nativeWindowState{}, nativeProbeFailure(nativeProbeConfigurationInvalid)
		}
		expectedTitle := C.CString("")
		if entryID != "" {
			C.free(unsafe.Pointer(expectedTitle))
			expectedTitle = C.CString(SecureEntryWindowTitlePrefix + entryID)
		}
		defer C.free(unsafe.Pointer(expectedTitle))
		var consoles, protected, matched C.int
		status := C.mechanize_vault_console_windows(C.uint(options.ExpectedUID), requirement, prefix, expectedTitle, &consoles, &protected, &matched)
		if ctx.Err() != nil {
			return nativeWindowState{}, nativeProbeFailure(nativeProbeContextExpired)
		}
		if status != 0 {
			return nativeWindowState{}, nativeProbeFailure(int(status))
		}
		return nativeWindowState{consoles: int(consoles), protected: protected != 0, entries: int(protected), matched: int(matched)}, nil
	}, nil
}
