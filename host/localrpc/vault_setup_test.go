package localrpc

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/viant/mechanize/auth"
)

func TestNativeVaultSetupClosedMetadataAndUnavailableProvider(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "setup-owner", []string{"consent:admin"})
	ctx := auth.WithPrincipal(context.Background(), p)
	s := &Server{}
	for _, method := range []string{"vault.status", "vault.setup"} {
		for _, extra := range []map[string]any{nil, {"key": "synthetic-key-canary"}, {"masterKey": "synthetic-key-canary"}, {"root": "/selected/by/client"}, {"keyReady": true}} {
			params := map[string]any{"sessionID": "fixture-session"}
			for k, v := range extra {
				params[k] = v
			}
			raw, _ := json.Marshal(params)
			reply := s.vaultSetup(ctx, request{JSONRPC: "2.0", ID: "setup", Method: method, Params: raw})
			if method == "vault.status" && extra == nil {
				if reply.Error != nil || reply.Result.(map[string]bool)["keyReady"] {
					t.Fatal("unconfigured setup reported ready")
				}
			} else if reply.Error == nil {
				t.Fatal("unconfigured or caller-selected setup admitted")
			}
		}
	}
	unverified, _ := auth.NewPrincipal("fixture", "", "setup-owner", nil)
	reply := s.vaultSetup(auth.WithPrincipal(context.Background(), unverified), request{Method: "vault.status", Params: json.RawMessage(`{"sessionID":"fixture"}`)})
	if reply.Error == nil {
		t.Fatal("setup without native admin authority")
	}
}
