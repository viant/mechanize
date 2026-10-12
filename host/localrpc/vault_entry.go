package localrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/vault"
)

// Lifecycle metadata is handled separately from generic RPC. No request may
// supply a cleanup boolean or native-window qualification assertion.
func (s *Server) vaultEntry(ctx context.Context, r request) (response, string, bool) {
	reply := response{JSONRPC: "2.0", ID: r.ID, Error: &rpcError{Code: -32020, Message: "native Vault unavailable or request rejected"}}
	if s.options.VaultEntry == nil || s.options.VaultInput == nil {
		return reply, "", false
	}
	human, err := auth.WithNativeHuman(ctx)
	if err != nil {
		return reply, "", false
	}
	bounded, cancel := context.WithTimeout(human, 10*time.Second)
	defer cancel()
	actor, _ := auth.FromContext(bounded)
	if s.options.AuthorizeVault == nil || s.options.AuthorizeVault(bounded, actor) != nil {
		return reply, "", false
	}
	decoder := json.NewDecoder(bytes.NewReader(r.Params))
	decoder.DisallowUnknownFields()
	if r.Method == "vault.entry.begin" {
		if s.options.VaultInput.Ready(bounded) != nil {
			return reply, "", false
		}
		var input struct {
			SessionID    string `json:"sessionID"`
			Origin       string `json:"origin"`
			AccountAlias string `json:"accountAlias"`
		}
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
			return reply, "", false
		}
		id, err := s.options.VaultEntry.Begin(bounded, vault.Target{Origin: input.Origin, Account: input.AccountAlias})
		if err != nil {
			return reply, "", false
		}
		reply.Error = nil
		reply.Result = map[string]string{"entryID": id}
		return reply, id, false
	}
	if r.Method == "vault.entry.bind" {
		var input struct {
			SessionID string `json:"sessionID"`
			EntryID   string `json:"entryID"`
			Origin    string `json:"origin"`
		}
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.EntryID == "" || s.options.VaultEntry.BindOrigin(bounded, input.EntryID, input.Origin) != nil {
			return reply, "", false
		}
		reply.Error = nil
		reply.Result = map[string]bool{"entryBound": true}
		return reply, "", false
	}
	if r.Method == "vault.entry.close" || r.Method == "vault.entry.confirm" {
		var input struct {
			SessionID string `json:"sessionID"`
			EntryID   string `json:"entryID"`
		}
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.EntryID == "" {
			return reply, "", false
		}
		if r.Method == "vault.entry.confirm" {
			err = s.options.VaultEntry.Confirm(bounded, input.EntryID)
			if err != nil {
				return reply, "", false
			}
			reply.Error = nil
			reply.Result = map[string]bool{"entryProtected": true}
			return reply, "", false
		}
		err = s.options.VaultEntry.Close(bounded, input.EntryID)
	} else if r.Method == "vault.entry.recover" {
		var input struct {
			SessionID string `json:"sessionID"`
		}
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
			return reply, "", false
		}
		err = s.options.VaultEntry.Recover(bounded)
	} else {
		return reply, "", false
	}
	if err != nil {
		return reply, "", false
	}
	reply.Error = nil
	reply.Result = map[string]bool{"entryClosed": true}
	return reply, "", true
}
