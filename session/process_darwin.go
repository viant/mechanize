//go:build darwin && cgo

package session

/*
#include <libproc.h>
#include <sys/proc_info.h>
#include <errno.h>
#include <unistd.h>
static int mechanize_identity(int pid, struct proc_bsdinfo *info, char *path, int capacity) {
 int n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, info, sizeof(*info));
 if (n != sizeof(*info)) { return errno == ESRCH ? 0 : -1; }
 if (info->pbi_status == 5) { return 0; } // public SZOMB status
 if (proc_pidpath(pid, path, capacity) <= 0) { return -1; }
 return 1;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func InspectProcess(pid int) (ProcessIdentity, bool, error) {
	if pid <= 0 {
		return ProcessIdentity{}, false, fmt.Errorf("invalid process PID")
	}
	var info C.struct_proc_bsdinfo
	path := make([]byte, 4096)
	result := C.mechanize_identity(C.int(pid), &info, (*C.char)(unsafe.Pointer(&path[0])), C.int(len(path)))
	if result == 0 {
		return ProcessIdentity{}, false, nil
	}
	if result < 0 {
		return ProcessIdentity{}, false, fmt.Errorf("public libproc identity inspection failed for PID %d", pid)
	}
	return ProcessIdentity{PID: pid, StartToken: fmt.Sprintf("%d:%d", info.pbi_start_tvsec, info.pbi_start_tvusec), Executable: C.GoString((*C.char)(unsafe.Pointer(&path[0]))), UID: uint32(info.pbi_uid)}, true, nil
}
