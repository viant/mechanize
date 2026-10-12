package localrpc

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/vault"
)

// This JSON header contains public routing only. Keys, named fields and values
// belong exclusively in the following protected MVLT v2 binary frame. Origin
// is deliberately absent: the internal entry binding is fixed by the server.
type vaultRecordRequest struct {
	SessionID    string
	EntryID      string
	AccountAlias string
	RefID        string
	Revision     string
}

func canonicalRecordHex(value string, size int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == size && hex.EncodeToString(decoded) == value
}
func decodeVaultRecordRequest(raw json.RawMessage, method string) (vaultRecordRequest, error) {
	var input vaultRecordRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return input, vault.ErrNativeInput
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return input, vault.ErrNativeInput
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			return input, vault.ErrNativeInput
		}
		seen[name] = true
		var destination *string
		switch name {
		case "sessionID":
			destination = &input.SessionID
		case "entryID":
			destination = &input.EntryID
		case "accountAlias":
			destination = &input.AccountAlias
		case "refID":
			destination = &input.RefID
		case "revision":
			destination = &input.Revision
		default:
			return input, vault.ErrNativeInput
		}
		// Decode into a pointer so JSON null is rejected as well as wrong types.
		var value *string
		if decoder.Decode(&value) != nil || value == nil {
			return input, vault.ErrNativeInput
		}
		*destination = *value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || decoder.Decode(new(any)) != io.EOF {
		return input, vault.ErrNativeInput
	}
	if !canonicalRecordHex(input.SessionID, 24) || !canonicalRecordHex(input.EntryID, 32) || (vault.Target{Origin: vault.NativeRecordEntryOrigin, Account: input.AccountAlias}).Validate() != nil {
		return input, vault.ErrNativeInput
	}
	switch method {
	case "vault.record.create":
		if seen["refID"] || seen["revision"] {
			return input, vault.ErrNativeInput
		}
	case "vault.record.update", "vault.record.delete":
		if !canonicalRecordHex(input.RefID, 32) || !canonicalRecordHex(input.Revision, 32) {
			return input, vault.ErrNativeInput
		}
	default:
		return input, vault.ErrNativeInput
	}
	return input, nil
}

func (s *Server) serveVaultRecord(c *net.UnixConn, ctx context.Context, r request, check func() error) {
	reply := response{JSONRPC: "2.0", ID: r.ID, Error: &rpcError{Code: -32020, Message: "native Vault record unavailable or request rejected"}}
	defer func() { _ = write(c, reply) }()
	if s.options.VaultRecords == nil || s.options.VaultEntry == nil || s.options.AuthorizeVault == nil || s.options.VerifyPeer == nil || check == nil || s.options.VerifyPeer(c) != nil || check() != nil {
		return
	}
	input, err := decodeVaultRecordRequest(r.Params, r.Method)
	if err != nil {
		return
	}
	native, err := auth.WithNativeHuman(ctx)
	if err != nil {
		return
	}
	bounded, cancel := context.WithTimeout(native, 15*time.Second)
	defer cancel()
	actor, err := auth.FromContext(bounded)
	if err != nil || s.options.AuthorizeVault(bounded, actor) != nil || s.options.VaultEntry.Authorize(bounded, input.EntryID) != nil {
		return
	}
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	target := vault.Target{Origin: vault.NativeRecordEntryOrigin, Account: input.AccountAlias}
	secretInput := &vaultReadyReader{connection: c, requestID: r.ID, check: func() error {
		if bounded.Err() != nil {
			return vault.ErrNativeInput
		}
		return check()
	}}
	var metadata vault.RecordMetadata
	ref := vault.RecordReference{ID: input.RefID}
	switch r.Method {
	case "vault.record.create":
		metadata, err = s.options.VaultRecords.Create(bounded, target, secretInput)
	case "vault.record.update":
		metadata, err = s.options.VaultRecords.Update(bounded, target, ref, input.Revision, secretInput)
	case "vault.record.delete":
		err = s.options.VaultRecords.Delete(bounded, target, ref, input.Revision)
	default:
		return
	}
	// Revalidate before acknowledging administration as well: a revoked signed
	// peer/enrollment after the final input read leaves an inspect-before-retry
	// outcome even if the encrypted mutation has already committed.
	if err == nil && (bounded.Err() != nil || check() != nil) {
		err = vault.ErrNativeOutcomeUnknown
	}
	if err != nil {
		if errors.Is(err, vault.ErrNativeOutcomeUnknown) {
			reply.Error = &rpcError{Code: -32021, Message: "native Vault record outcome requires inspection before another attempt"}
		}
		return
	}
	reply.Error = nil
	if r.Method == "vault.record.delete" {
		reply.Result = struct {
			Deleted bool `json:"deleted"`
		}{Deleted: true}
	} else {
		reply.Result = metadata
	}
}
