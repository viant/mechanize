//go:build darwin && cgo

package nativepeer

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <libproc.h>
#include <sys/proc_info.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
static int mechanize_parent_info(int pid, struct proc_bsdinfo *info, char *path, int capacity) {
 int count=proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, info, sizeof(*info));
 if(count!=sizeof(*info)||info->pbi_status==5||proc_pidpath(pid,path,capacity)<=0)return -1;
 return 0;
}
static OSStatus mechanize_dynamic_pid_verify(int pid,const char *text) {
 CFNumberRef number=CFNumberCreate(NULL,kCFNumberIntType,&pid);
 if(!number)return errSecAllocate;
 const void *keys[]={kSecGuestAttributePid};const void *values[]={number};
 CFDictionaryRef attributes=CFDictionaryCreate(NULL,keys,values,1,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
 CFRelease(number);if(!attributes)return errSecAllocate;
 SecCodeRef code=NULL;OSStatus status=SecCodeCopyGuestWithAttributes(NULL,attributes,kSecCSDefaultFlags,&code);CFRelease(attributes);
 if(status!=errSecSuccess)return status;
 CFStringRef string=CFStringCreateWithCString(NULL,text,kCFStringEncodingUTF8);SecRequirementRef requirement=NULL;
 if(!string){CFRelease(code);return errSecAllocate;}
 status=SecRequirementCreateWithString(string,kSecCSDefaultFlags,&requirement);CFRelease(string);
 if(status==errSecSuccess)status=SecCodeCheckValidity(code,kSecCSStrictValidate,requirement);
 if(requirement)CFRelease(requirement);CFRelease(code);return status;
}
*/
import "C"
import (
	"fmt"
	"github.com/viant/mechanize/session"
	"unsafe"
)

func inspectProcessParent(pid int) (processParent, error) {
	if pid <= 0 {
		return processParent{}, fmt.Errorf("invalid ancestry PID")
	}
	var info C.struct_proc_bsdinfo
	path := make([]byte, 4096)
	if C.mechanize_parent_info(C.int(pid), &info, (*C.char)(unsafe.Pointer(&path[0])), C.int(len(path))) != 0 {
		return processParent{}, fmt.Errorf("public libproc ancestry unavailable")
	}
	return processParent{identity: session.ProcessIdentity{PID: pid, UID: uint32(info.pbi_uid), Executable: C.GoString((*C.char)(unsafe.Pointer(&path[0]))), StartToken: fmt.Sprintf("%d:%d", info.pbi_start_tvsec, info.pbi_start_tvusec)}, parentPID: int(info.pbi_ppid)}, nil
}
func verifyDynamicProcess(pid int, requirement string) error {
	text := C.CString(requirement)
	defer C.free(unsafe.Pointer(text))
	if status := C.mechanize_dynamic_pid_verify(C.int(pid), text); status != 0 {
		return fmt.Errorf("enrolled ancestry code denied (Security status %d)", int(status))
	}
	return nil
}
