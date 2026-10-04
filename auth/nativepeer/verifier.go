// Package nativepeer authenticates the enrolled native console on a Unix socket.
package nativepeer

import (
	"errors"
	"net"
	"strings"
)

var ErrUnsupported = errors.New("signed native peer verification requires macOS with cgo")

type Options struct {
	ExpectedUID uint32
	// DesignatedRequirement must come from trusted operator configuration.
	DesignatedRequirement string
}

// NewVerifier compiles the configured Security.framework requirement and returns
// a verifier bound to that requirement. UID is necessary but never sufficient.
func NewVerifier(o Options) (func(*net.UnixConn) error, error) {
	if strings.TrimSpace(o.DesignatedRequirement) == "" || strings.ContainsRune(o.DesignatedRequirement, 0) {
		return nil, errors.New("native peer requires a nonempty code requirement")
	}
	return newVerifier(o)
}
