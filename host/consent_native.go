package host

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/host/localrpc"
	"github.com/viant/mechanize/vault"
	"net"
)

// NativePeerVerify must establish the enrolled console's signed executable and
// audit identity from the accepted Unix connection. A claimed bundle ID or UID
// match is insufficient. Production must supply the platform verifier.
type NativePeerVerify func(*net.UnixConn) error

type ConsentListenerOptions struct {
	SocketPath    string
	Verifier      localrpc.CredentialVerifier
	VerifyPeer    NativePeerVerify
	Broker        *ConsentBroker
	Additional    localrpc.Handler
	VaultInput    *vault.NativeInputService
	VaultEntry    *vault.NativeEntryController
	VaultKeySetup *vault.NativeKeySetup
	VaultRecords  *vault.NativeRecordInputService
}

// OpenConsentListener asserts human transport authority only after localrpc has
// verified both the peer and Scy consent:admin credential. No fallback exists.
func OpenConsentListener(ctx context.Context, o ConsentListenerOptions) (*localrpc.Server, error) {
	if o.Broker == nil || o.VerifyPeer == nil || o.Verifier == nil {
		return nil, errors.New("native console requires signed peer verification, Scy admin credentials and consent broker")
	}
	return localrpc.New(ctx, localrpc.Options{SocketPath: o.SocketPath, Verifier: o.Verifier, VerifyPeer: o.VerifyPeer, VaultInput: o.VaultInput, VaultEntry: o.VaultEntry, VaultKeySetup: o.VaultKeySetup, VaultRecords: o.VaultRecords, AuthorizeVault: func(c context.Context, p auth.Principal) error { _, err := o.Broker.options.Enrolled(c, p); return err }, Handle: func(ctx context.Context, method string, raw json.RawMessage) (any, error) {
		human, e := auth.WithNativeHuman(ctx)
		if e != nil {
			return nil, e
		}
		if method == "migration.managementProof" || method == "credential.pending" || method == "credential.bind" || method == "credential.cancel" || method == "inventory" || method == "helperPermissionDoctor" || method == "applicationAccess.get" || method == "applicationAccess.set" || method == "browserStatus" || method == "browserSetupMetadata" || method == "browserControllers" || method == "settings.get" || method == "settings.port.set" {
			if o.Additional != nil {
				return o.Additional(human, method, raw)
			}
			if method == "migration.managementProof" || method == "browserSetupMetadata" || method == "browserControllers" {
				return nil, errors.New("native browser setup metadata provider unavailable")
			}
			return []any{}, nil
		}
		return o.Broker.NativeRPC(human, method, raw)
	}})
}
