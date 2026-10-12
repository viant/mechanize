package host

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
)

// Metadata-only restart regression: no Host pending session, browser, Vault,
// files, or persistent ledger is accessed. All scalar records are synthetic.
func TestRestartProtectionAbsenceSourcesFromDurableMetadata(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "source-owner", []string{"desktop:control"})
	p.ClientID = "client"
	prep := data.CredentialPreparationRecord{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: "old-session", PreparationID: strings.Repeat("a", 64), GrantID: "old-grant", PurposeHash: data.CredentialDeliveryPurposeHash("login"), Origin: "https://fixture.invalid", SelectedRevision: strings.Repeat("b", 64), ProtectionState: "held", Revision: 1}
	row := data.CredentialDeliveryRecord{Namespace: prep.Namespace, ClientID: prep.ClientID, SessionID: prep.SessionID, SelectionID: prep.PreparationID, GrantID: prep.GrantID, PurposeHash: prep.PurposeHash, SelectedRevision: prep.SelectedRevision, Origin: prep.Origin, ProfileChannel: "profile", BrowserInstance: "browser", TabID: 7, DocumentID: "source-document", DocumentGeneration: 1, ChromeStartToken: "123:456", BrokerEpoch: "broker", ChannelEpoch: "channel", ScopeHash: strings.Repeat("c", 64), DispatchState: "dispatched", ProtectionState: "held", Revision: 2}
	snapshot := durable.CredentialProtection{Scope: data.CredentialProtectionScopeRecord{Namespace: p.Namespace, ClientID: p.ClientID, PreparationID: prep.PreparationID, Origin: prep.Origin}, Preparation: prep, Attempts: []data.CredentialDeliveryRecord{row, row}}
	for _, captured := range []bool{false, true} {
		current := snapshot
		if captured {
			current.Scope = protectionScopeRecord(p, chrome.CredentialProtectionScope{PreparationID: prep.PreparationID, Identity: chrome.Identity{ProfileChannel: row.ProfileChannel, BrowserInstance: row.BrowserInstance, TabID: row.TabID, FrameID: 0, DocumentID: row.DocumentID, Generation: 1}, Origin: prep.Origin, ChromeStartToken: row.ChromeStartToken, BrokerEpoch: row.BrokerEpoch, ChannelEpoch: row.ChannelEpoch, ScopeHash: row.ScopeHash, LoginRouteSHA256: strings.Repeat("d", 64)})
		}
		raw, _ := json.Marshal(current)
		var restored durable.CredentialProtection
		if e := json.Unmarshal(raw, &restored); e != nil {
			t.Fatal(e)
		}
		sources, e := protectionAbsenceSources(p, restored)
		if e != nil || len(sources) != 1 || sources[0].Identity.DocumentID != row.DocumentID || sources[0].PreparationID != prep.PreparationID {
			t.Fatal("valid restarted metadata failed before browser proof", captured, e)
		}
	}
	for _, field := range []string{"parent", "client", "session", "grant", "purpose", "revision", "origin", "document", "birth"} {
		bad := snapshot
		bad.Attempts = append([]data.CredentialDeliveryRecord(nil), snapshot.Attempts...)
		switch field {
		case "parent":
			bad.Preparation.PreparationID = "other"
		case "client":
			bad.Attempts[0].ClientID = "other"
		case "session":
			bad.Attempts[0].SessionID = "other"
		case "grant":
			bad.Attempts[0].GrantID = "other"
		case "purpose":
			bad.Attempts[0].PurposeHash = ""
		case "revision":
			bad.Attempts[0].SelectedRevision = "other"
		case "origin":
			bad.Attempts[0].Origin = "https://different.invalid"
		case "document":
			bad.Attempts[0].DocumentID = ""
		case "birth":
			bad.Attempts[0].ChromeStartToken = ""
		}
		if _, e := protectionAbsenceSources(p, bad); e == nil {
			t.Fatal("incomplete lineage accepted", field)
		}
	}
}
