package chrome

import (
	"errors"
	"net"
	"time"

	"github.com/viant/mechanize/auth/nativepeer"
)

// This pre-enrollment response carries no channel, credential or process data.
// It never admits the peer, and a stalled rejected peer cannot hold the broker.
func rejectNativeStartup(conn net.Conn, code string) {
	_ = conn.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
	_ = WriteFrame(conn, struct {
		Type string `json:"type"`
		Code string `json:"code"`
	}{"nativeHostError", code})
}

func brokerStartupPeerCode(err error) string {
	switch {
	case errors.Is(err, nativepeer.ErrNativePeerAuthentication):
		return "brokerPeerUnavailable"
	case errors.Is(err, nativepeer.ErrNativePeerAudit):
		return "brokerPeerAuditUnavailable"
	default:
		return "brokerProcessUnqualified"
	}
}
