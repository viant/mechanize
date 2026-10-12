package localrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/vault"
)

type vaultImportRequest struct {
	SessionID    string `json:"sessionID"`
	EntryID      string `json:"entryID"`
	Origin       string `json:"origin"`
	AccountAlias string `json:"accountAlias"`
	ResourceURL  string `json:"resourceURL"`
	Revision     string `json:"revision"`
}

func decodeVaultImport(raw []byte) (vaultImportRequest, error) {
	var in vaultImportRequest
	if len(raw) > 8192 {
		return in, vault.ErrNativeInput
	}
	// This closed metadata request never accepts credentials, file paths, cipher
	// configuration or a caller approval/protection assertion.
	d := json.NewDecoder(bytes.NewReader(raw))
	token, e := d.Token()
	if e != nil || token != json.Delim('{') {
		return in, vault.ErrNativeInput
	}
	seen := map[string]bool{}
	for d.More() {
		token, e = d.Token()
		key, ok := token.(string)
		if e != nil || !ok || seen[key] {
			return in, vault.ErrNativeInput
		}
		seen[key] = true
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return in, vault.ErrNativeInput
		}
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF || len(seen) != 6 || !canonicalRecordHex(in.SessionID, 24) || !canonicalRecordHex(in.EntryID, 32) || !canonicalRecordHex(in.Revision, 32) || (vault.Target{Origin: in.Origin, Account: in.AccountAlias}).Validate() != nil || in.ResourceURL == "" {
		return in, vault.ErrNativeInput
	}
	return in, nil
}
func (s *Server) vaultImport(ctx context.Context, r request, check func() error) response {
	reply := response{JSONRPC: "2.0", ID: r.ID, Error: &rpcError{Code: -32020, Message: "native credential import unavailable"}}
	if s.options.VaultRecords == nil || s.options.VaultInput == nil || s.options.VaultEntry == nil || s.options.AuthorizeVault == nil || check == nil || check() != nil {
		return reply
	}
	input, e := decodeVaultImport(r.Params)
	if e != nil {
		return reply
	}
	human, e := auth.WithNativeHuman(ctx)
	if e != nil {
		return reply
	}
	bounded, cancel := context.WithTimeout(human, 15*time.Second)
	defer cancel()
	p, e := auth.FromContext(bounded)
	if e != nil || s.options.AuthorizeVault(bounded, p) != nil || s.options.VaultEntry.Authorize(bounded, input.EntryID) != nil {
		return reply
	}
	inspect := r.Method == "vault.record.inspectImport"
	if !inspect && r.Method != "vault.record.importCredential" {
		return reply
	}
	metadata, e := s.options.VaultRecords.ImportCredential(bounded, s.options.VaultInput, vault.Target{Origin: input.Origin, Account: input.AccountAlias}, vault.Reference{ResourceURL: input.ResourceURL}, input.Revision, inspect)
	if e == nil && (check() != nil || bounded.Err() != nil) {
		e = vault.ErrNativeOutcomeUnknown
	}
	if e != nil {
		if errors.Is(e, vault.ErrNativeOutcomeUnknown) {
			reply.Error = &rpcError{Code: -32021, Message: "native credential import requires inspection; do not copy again"}
		}
		return reply
	}
	reply.Error = nil
	reply.Result = metadata
	return reply
}
