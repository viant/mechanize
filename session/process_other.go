//go:build !darwin || !cgo

package session

import "errors"

func InspectProcess(pid int) (ProcessIdentity, bool, error) {
	return ProcessIdentity{}, false, errors.New("native process identity requires macOS public libproc and cgo")
}
