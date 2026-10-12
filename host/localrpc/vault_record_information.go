package localrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/viant/mechanize/auth"
)

func recordInformationSession(raw json.RawMessage) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return false
	}
	if !decoder.More() {
		return false
	}
	if token, err := decoder.Token(); err != nil || token != "sessionID" {
		return false
	}
	var session *string
	if decoder.Decode(&session) != nil || session == nil || !canonicalRecordHex(*session, 24) || decoder.More() {
		return false
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return false
	}
	return decoder.Decode(new(any)) == io.EOF
}

func (s *Server) vaultRecordInformation(ctx context.Context, r request) response {
	reply := response{JSONRPC: "2.0", ID: r.ID, Error: &rpcError{Code: -32020, Message: "native Vault record information unavailable"}}
	if !recordInformationSession(r.Params) {
		return reply
	}
	human, err := auth.WithNativeHuman(ctx)
	if err != nil {
		return reply
	}
	bounded, cancel := context.WithTimeout(human, 10*time.Second)
	defer cancel()
	actor, err := auth.FromContext(bounded)
	if err != nil || s.options.AuthorizeVault == nil || s.options.AuthorizeVault(bounded, actor) != nil {
		return reply
	}
	if r.Method == "vault.record.status" {
		ready := s.options.VaultRecords != nil && s.options.VaultEntry != nil && s.options.VaultRecords.Ready(bounded) == nil
		reply.Error = nil
		reply.Result = map[string]bool{"recordReady": ready}
		return reply
	}
	if r.Method != "vault.record.inventory" || s.options.VaultRecords == nil {
		return reply
	}
	rows, err := s.options.VaultRecords.Inventory(bounded)
	if err != nil {
		return reply
	}
	reply.Error = nil
	reply.Result = map[string]any{"entries": rows}
	return reply
}
