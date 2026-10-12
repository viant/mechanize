package localrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/vault"
)

// Only public origin/opaque-account/revision metadata is framed JSON. The
// following single binary credential pair is consumed inside the protected
// native service, after signed-peer and Scy authentication have succeeded.
type vaultRequest struct {
	SessionID    string `json:"sessionID"`
	Origin       string `json:"origin"`
	AccountAlias string `json:"accountAlias"`
	Revision     string `json:"revision,omitempty"`
	EntryID      string `json:"entryID,omitempty"`
}
type vaultResult struct {
	Reference *vault.Reference `json:"reference,omitempty"`
	Deleted   bool             `json:"deleted,omitempty"`
}

// The service performs its authority/target/protection checks before its first
// credential read. Only then acknowledge that the native sender may release
// the binary frame. A disabled or rejected channel never requests its bytes.
type vaultReadyReader struct {
	connection *net.UnixConn
	requestID  string
	ready      bool
	check      func() error
}

func (r *vaultReadyReader) Read(b []byte) (int, error) {
	if r.check == nil || r.check() != nil {
		return 0, vault.ErrNativeInput
	}
	if !r.ready {
		if err := write(r.connection, response{JSONRPC: "2.0", ID: r.requestID, Result: map[string]bool{"nativeInputReady": true}}); err != nil {
			return 0, err
		}
		r.ready = true
	}
	return r.connection.Read(b)
}

func (s *Server) serveVault(c *net.UnixConn, ctx context.Context, r request, check func() error) {
	reply := response{JSONRPC: "2.0", ID: r.ID, Error: &rpcError{Code: -32020, Message: "native Vault unavailable or request rejected"}}
	defer func() { _ = write(c, reply) }()
	if s.options.VaultInput == nil || s.options.VerifyPeer(c) != nil {
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(r.Params))
	decoder.DisallowUnknownFields()
	var input vaultRequest
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		return
	}
	if r.Method == "vault.create" && input.Revision != "" || r.Method != "vault.create" && input.Revision == "" {
		return
	}
	native, err := auth.WithNativeHuman(ctx)
	if err != nil {
		return
	}
	if s.options.VaultEntry != nil && s.options.VaultEntry.Authorize(native, input.EntryID) != nil {
		return
	}
	if s.options.VaultEntry == nil && input.EntryID != "" {
		return
	}
	bounded, cancel := context.WithTimeout(native, 15*time.Second)
	defer cancel()
	actor, _ := auth.FromContext(bounded)
	if s.options.AuthorizeVault == nil || s.options.AuthorizeVault(bounded, actor) != nil {
		return
	}
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	target := vault.Target{Origin: input.Origin, Account: input.AccountAlias}
	secretInput := &vaultReadyReader{connection: c, requestID: r.ID, check: check}
	var ref vault.Reference
	switch r.Method {
	case "vault.create":
		ref, err = s.options.VaultInput.Create(bounded, target, secretInput)
	case "vault.update":
		ref, err = s.options.VaultInput.Update(bounded, target, input.Revision, secretInput)
	case "vault.delete":
		err = s.options.VaultInput.Delete(bounded, target, input.Revision)
	default:
		return
	}
	if err != nil {
		if errors.Is(err, vault.ErrNativeOutcomeUnknown) {
			reply.Error = &rpcError{Code: -32021, Message: "native Vault outcome requires inspection before another attempt"}
		}
		return
	}
	reply.Error = nil
	if r.Method == "vault.delete" {
		reply.Result = vaultResult{Deleted: true}
	} else {
		reply.Result = vaultResult{Reference: &ref}
	}
}
