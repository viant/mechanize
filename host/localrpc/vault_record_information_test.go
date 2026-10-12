package localrpc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/vault"
)

func TestRecordInformationRejectsSecretExtraDuplicateAndMalformedMetadata(t *testing.T) {
	session := strings.Repeat("a", 48)
	valid := `{"sessionID":"` + session + `"}`
	if !recordInformationSession([]byte(valid)) {
		t.Fatal("canonical metadata rejected")
	}
	for _, raw := range []string{`{}`, `{"sessionID":null}`, `{"sessionID":"bad"}`, valid + `{}`,
		`{"sessionID":"` + session + `","sessionID":"` + session + `"}`,
		`{"sessionID":"` + session + `","value":"private-canary"}`} {
		if recordInformationSession([]byte(raw)) {
			t.Fatal("noncanonical information request accepted")
		}
	}
}

func TestRecordInformationReadinessInventoryAndEnrollment(t *testing.T) {
	f := newRecordSocketFixture(t)
	s := &Server{options: f.options}
	params := json.RawMessage(`{"sessionID":"` + strings.Repeat("a", 48) + `"}`)
	request := request{JSONRPC: "2.0", ID: "record-information", Method: "vault.record.status", Params: params}
	response := s.vaultRecordInformation(f.human, request)
	if response.Error != nil || response.Result.(map[string]bool)["recordReady"] != true {
		t.Fatal("ready record service rejected")
	}
	values, err := vault.NewRecordValues([]byte("private-key-canary"), [][2][]byte{{[]byte("private-name-canary"), []byte("private-value-canary")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.Create(f.human, values); err != nil {
		t.Fatal(err)
	}
	request.Method = "vault.record.inventory"
	response = s.vaultRecordInformation(f.human, request)
	if response.Error != nil {
		t.Fatal("opaque inventory unavailable")
	}
	encoded, err := json.Marshal(response.Result)
	if err != nil || strings.Contains(string(encoded), "canary") {
		t.Fatal("inventory disclosed a key, name or value")
	}
	s.options.AuthorizeVault = func(_ctx context.Context, _ auth.Principal) error { return errors.New("private-error-canary") }
	if response = s.vaultRecordInformation(f.human, request); response.Error == nil || strings.Contains(response.Error.Message, "canary") {
		t.Fatal("unregistered information request admitted")
	}
}
