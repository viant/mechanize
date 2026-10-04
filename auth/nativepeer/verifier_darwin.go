//go:build darwin && cgo

package nativepeer

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -lbsm
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <bsm/libbsm.h>
#include <unistd.h>
#include <stdlib.h>

static OSStatus mechanize_requirement(const char *text, SecRequirementRef *requirement) {
 CFStringRef value = CFStringCreateWithCString(NULL, text, kCFStringEncodingUTF8);
 if (!value) return errSecParam;
 OSStatus status = SecRequirementCreateWithString(value, kSecCSDefaultFlags, requirement);
 CFRelease(value);
 return status;
}
static OSStatus mechanize_parse_requirement(const char *text) {
 SecRequirementRef requirement = NULL;
 OSStatus status = mechanize_requirement(text, &requirement);
 if (requirement) CFRelease(requirement);
 return status;
}
static OSStatus mechanize_verify_peer(int fd, unsigned int expectedUID, const char *text) {
 uid_t uid; gid_t gid;
 if (getpeereid(fd, &uid, &gid) != 0 || uid != expectedUID) return errSecAuthFailed;
 audit_token_t token;
 socklen_t size = sizeof(token);
 // The audit token includes pidversion; Security.framework resolves the exact
 // socket peer, so PID reuse cannot authenticate a replacement process.
 if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) != 0 || size != sizeof(token)) return errSecAuthFailed;
 if (audit_token_to_euid(token) != expectedUID) return errSecAuthFailed;
 CFDataRef data = CFDataCreate(NULL, (const UInt8 *)&token, sizeof(token));
 if (!data) return errSecAllocate;
 const void *keys[] = { kSecGuestAttributeAudit };
 const void *values[] = { data };
 CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
 CFRelease(data);
 if (!attributes) return errSecAllocate;
 SecCodeRef code = NULL;
 OSStatus status = SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code);
 CFRelease(attributes);
 if (status != errSecSuccess) return status;
 SecRequirementRef requirement = NULL;
 status = mechanize_requirement(text, &requirement);
 if (status == errSecSuccess) status = SecCodeCheckValidity(code, kSecCSStrictValidate, requirement);
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

func newVerifier(o Options) (func(*net.UnixConn) error, error) {
	text := C.CString(o.DesignatedRequirement)
	status := C.mechanize_parse_requirement(text)
	C.free(unsafe.Pointer(text))
	if status != 0 {
		return nil, fmt.Errorf("invalid native code requirement (Security status %d)", int(status))
	}
	return func(conn *net.UnixConn) error {
		if conn == nil {
			return fmt.Errorf("native peer connection is required")
		}
		raw, err := conn.SyscallConn()
		if err != nil {
			return fmt.Errorf("native peer socket unavailable: %w", err)
		}
		text := C.CString(o.DesignatedRequirement)
		defer C.free(unsafe.Pointer(text))
		var status C.OSStatus
		if err = raw.Control(func(fd uintptr) { status = C.mechanize_verify_peer(C.int(fd), C.uint(o.ExpectedUID), text) }); err != nil {
			return fmt.Errorf("native peer socket verification failed: %w", err)
		}
		if status != 0 {
			return fmt.Errorf("native peer authentication denied (Security status %d)", int(status))
		}
		return nil
	}, nil
}
