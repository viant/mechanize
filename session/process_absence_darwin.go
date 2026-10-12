//go:build darwin && cgo

package session

/*
#include <libproc.h>
#include <sys/proc_info.h>
#include <errno.h>
static int mechanize_birth_only(int pid,struct proc_bsdinfo *info){errno=0;int n=proc_pidinfo(pid,PROC_PIDTBSDINFO,0,info,sizeof(*info));if(n!=sizeof(*info))return errno==ESRCH?0:-1;if(info->pbi_pid!=(uint32_t)pid)return -1;if(info->pbi_status==5)return 0;return 1;}
*/
import "C"
import "unsafe"
import "fmt"

func listUIDProcesses(uid uint32) ([]int, error) {
	capacity := 256
	for capacity <= 131072 {
		buf := make([]C.int, capacity)
		n := int(C.proc_listpids(C.PROC_UID_ONLY, C.uint32_t(uid), unsafe.Pointer(&buf[0]), C.int(len(buf)*4)))
		if n <= 0 || n%4 != 0 {
			return nil, ErrProcessAbsenceUnavailable
		}
		if n >= len(buf)*4 {
			capacity *= 2
			continue
		}
		out := []int{}
		for _, pid := range buf[:n/4] {
			if pid > 0 {
				out = append(out, int(pid))
			}
		}
		return out, nil
	}
	return nil, ErrProcessAbsenceUnavailable
}

func inspectProcessBirth(pid int) (ProcessIdentity, bool, error) {
	if pid <= 0 {
		return ProcessIdentity{}, false, ErrProcessAbsenceUnavailable
	}
	var info C.struct_proc_bsdinfo
	n := C.mechanize_birth_only(C.int(pid), &info)
	if n == 0 {
		return ProcessIdentity{}, false, nil
	}
	if n < 0 {
		return ProcessIdentity{}, false, ErrProcessAbsenceUnavailable
	}
	return ProcessIdentity{PID: pid, UID: uint32(info.pbi_uid), StartToken: fmt.Sprintf("%d:%d", info.pbi_start_tvsec, info.pbi_start_tvusec)}, true, nil
}
