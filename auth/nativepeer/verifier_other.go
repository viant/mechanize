//go:build !darwin || !cgo

package nativepeer

import "net"

func newVerifier(Options) (func(*net.UnixConn) error, error) { return nil, ErrUnsupported }
