package localrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/viant/mechanize/auth"
)

func (s *Server) vaultSetup(ctx context.Context, r request) response {
	reply := response{JSONRPC: "2.0", ID: r.ID, Error: &rpcError{Code: -32020, Message: "native Vault setup unavailable or request rejected"}}
	decoder := json.NewDecoder(bytes.NewReader(r.Params))
	decoder.DisallowUnknownFields()
	var input struct {
		SessionID string `json:"sessionID"`
	}
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		return reply
	}
	human, err := auth.WithNativeHuman(ctx)
	if err != nil {
		return reply
	}
	bounded, cancel := context.WithTimeout(human, 10*time.Second)
	defer cancel()
	if s.options.VaultInput != nil {
		actor, _ := auth.FromContext(bounded)
		if s.options.AuthorizeVault == nil || s.options.AuthorizeVault(bounded, actor) != nil {
			return reply
		}
	}
	if r.Method == "vault.status" {
		ready := s.options.VaultKeySetup != nil && s.options.VaultEntry != nil && s.options.VaultKeySetup.Ready(bounded) == nil
		reply.Error = nil
		reply.Result = map[string]bool{"keyReady": ready}
		return reply
	}
	if r.Method == "vault.inventory" {
		if s.options.VaultInput == nil {
			return reply
		}
		rows, err := s.options.VaultInput.Inventory(bounded)
		if err != nil {
			return reply
		}
		reply.Error = nil
		reply.Result = map[string]any{"entries": rows}
		return reply
	}
	if r.Method != "vault.setup" || s.options.VaultKeySetup == nil || s.options.VaultEntry == nil || s.options.VaultKeySetup.Ensure(bounded) != nil {
		return reply
	}
	reply.Error = nil
	reply.Result = map[string]bool{"keyReady": true}
	return reply
}
