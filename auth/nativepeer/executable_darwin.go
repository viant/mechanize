//go:build darwin && cgo

package nativepeer

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -lbsm
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <bsm/libbsm.h>
#include <stdlib.h>
#include <string.h>

static int mechanize_audit_pid(int fd) {
 audit_token_t token;
 socklen_t size = sizeof(token);
 if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) != 0 || size != sizeof(token)) return -1;
 return audit_token_to_pid(token);
}
static OSStatus mechanize_static_verify(const char *path, const char *text) {
 CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, strlen(path), false);
 if (!url) return errSecParam;
 SecStaticCodeRef code = NULL;
 OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
 CFRelease(url);
 if (status != errSecSuccess) return status;
 CFStringRef value = CFStringCreateWithCString(NULL, text, kCFStringEncodingUTF8);
 SecRequirementRef requirement = NULL;
 if (!value) { CFRelease(code); return errSecAllocate; }
 status = SecRequirementCreateWithString(value, kSecCSDefaultFlags, &requirement);
 CFRelease(value);
 if (status == errSecSuccess) status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures, requirement);
 if (requirement) CFRelease(requirement);
 CFRelease(code);
 return status;
}
*/
import "C"

import (
	"fmt"
	"net"
	"unsafe"
)

func verifyExecutable(path string, options Options) error {
	p, r := C.CString(path), C.CString(options.DesignatedRequirement)
	defer C.free(unsafe.Pointer(p))
	defer C.free(unsafe.Pointer(r))
	if status := C.mechanize_static_verify(p, r); status != 0 {
		return fmt.Errorf("enrolled executable code verification denied (Security status %d)", int(status))
	}
	return nil
}
func auditPID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	pid := -1
	if err = raw.Control(func(fd uintptr) { pid = int(C.mechanize_audit_pid(C.int(fd))) }); err != nil {
		return 0, err
	}
	if pid <= 0 {
		return 0, fmt.Errorf("kernel native peer audit PID unavailable")
	}
	return pid, nil
}
