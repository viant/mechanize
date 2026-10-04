package host

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/host/localrpc"
	"net"
)

// NativePeerVerify must establish the enrolled console's signed executable and
// audit identity from the accepted Unix connection. A claimed bundle ID or UID
// match is insufficient. Production must supply the platform verifier.
type NativePeerVerify func(*net.UnixConn) error

type ConsentListenerOptions struct {
	SocketPath string
	Verifier   localrpc.CredentialVerifier
	VerifyPeer NativePeerVerify
	Broker     *ConsentBroker
	Additional localrpc.Handler
}

// OpenConsentListener asserts human transport authority only after localrpc has
// verified both the peer and Scy consent:admin credential. No fallback exists.
func OpenConsentListener(ctx context.Context, o ConsentListenerOptions) (*localrpc.Server, error) {
	if o.Broker == nil || o.VerifyPeer == nil || o.Verifier == nil {
		return nil, errors.New("native console requires signed peer verification, Scy admin credentials and consent broker")
	}
	return localrpc.New(ctx, localrpc.Options{SocketPath: o.SocketPath, Verifier: o.Verifier, VerifyPeer: o.VerifyPeer, Handle: func(ctx context.Context, method string, raw json.RawMessage) (any, error) {
		human, e := auth.WithNativeHuman(ctx)
		if e != nil {
			return nil, e
		}
		if method == "inventory" || method == "helperPermissionDoctor" || method == "applicationAccess.get" || method == "applicationAccess.set" {
			if o.Additional != nil {
				return o.Additional(human, method, raw)
			}
			return []any{}, nil
		}
		return o.Broker.NativeRPC(human, method, raw)
	}})
}
