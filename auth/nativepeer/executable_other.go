//go:build !darwin || !cgo

package nativepeer

import "net"

func verifyExecutable(string, Options) error { return ErrUnsupported }
func auditPID(*net.UnixConn) (int, error)    { return 0, ErrUnsupported }
