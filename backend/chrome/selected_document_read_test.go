package chrome

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSelectedFreshDocumentPublicReadRetainsUnrelatedUnknownAndJournal(t *testing.T) {
	f, c, ctx := publicReadFixture(t)
	b := f.g.broker
	original := strings.Repeat("c", 64)
	b.mu.Lock()
	c.credentialPublicReadVersion = 2
	c.executorQualified = false
	c.inventoryComplete = false
	c.attentionCode = "storedFenceMismatch"
	c.reconnectPhase = "journal"
	c.reconnectReason = "journalChanged"
	c.reconnectJournal = &ReconnectJournalDiagnostic{Reason: "historyLimit", Version: 4, HistoryCount: 49, State: "pending", GrantRelation: "old"}
	c.unknown[original] = true
	c.attempts[original] = Command{Action: "element.press", AttemptID: original, Identity: Identity{ProfileChannel: "p1", BrowserInstance: "b1", TabID: 5, FrameID: 0, DocumentID: "old-uncertain-document", Generation: 1}, BrokerEpoch: "original-broker", ChannelEpoch: "original-channel", ScopeHash: c.scopeHash, FingerprintVersion: 2, FingerprintSHA256: strings.Repeat("d", 64)}
	snapshot := func() []byte {
		value, _ := json.Marshal(struct {
			Attempts                 map[string]Command
			Receipts                 map[string]Reply
			Unknown                  map[string]bool
			Journal                  *ReconnectJournalDiagnostic
			Attention, Phase, Reason string
		}{c.attempts, c.receipts, c.unknown, c.reconnectJournal, c.attentionCode, c.reconnectPhase, c.reconnectReason})
		return value
	}
	before := snapshot()
	b.mu.Unlock()
	verified, e := f.g.WithVerifiedCredentialPublicRead(ctx, f.p, readTarget().Surface)
	if e != nil {
		t.Fatal("fresh selected public document blocked by unrelated historic uncertainty", e)
	}
	if _, e = f.g.Observe(verified, f.p, readTarget().Surface); e != nil {
		t.Fatal("classified current observation", e)
	}
	pin, e := f.g.PinReadDocument(verified, f.p, readTarget().Surface)
	if e != nil {
		t.Fatal(e)
	}
	value, _, e := f.g.ReadPinned(verified, f.p, pin, readTarget(), "value", nil)
	if e != nil || value.String != "independent-result" {
		t.Fatal("classified current read", value, e)
	}
	oldSurface := readTarget().Surface
	oldSurface.TabID = "p1/b1/5"
	if _, e = f.g.AdmitControl(ctx, f.p, oldSurface); e == nil {
		t.Fatal("old uncertain renderer acquired input authority")
	}
	if _, e = f.g.AdmitControl(verified, f.p, readTarget().Surface); e == nil {
		t.Fatal("public-read proof granted a mutation lease")
	}
	b.mu.Lock()
	after := snapshot()
	retained := !c.executorQualified && !c.inventoryComplete && len(c.documents) == 0 && c.privacy != nil
	b.mu.Unlock()
	if string(before) != string(after) || !retained || f.mutations.Load() != 0 || f.acquireCalls.Load() != 0 {
		t.Fatal("read changed original request/journal or dispatched input")
	}
	if f.publicReadMarked.Load() == 0 {
		t.Fatal("fresh read did not use existing bounded semantic read protocol")
	}
}

func TestSelectedDocumentPublicReadKeepsLegacyPrivateAndMutationBarriers(t *testing.T) {
	for _, mode := range []string{"legacy", "private", "foreignProfile", "wrongDocument", "notPublic", "activePrivateInput", "lifecycle"} {
		t.Run(mode, func(t *testing.T) {
			f, c, ctx := publicReadFixture(t)
			b := f.g.broker
			b.mu.Lock()
			c.credentialPublicReadVersion = 2
			c.executorQualified = false
			c.inventoryComplete = false
			c.unknown["original-unknown"] = true
			if mode == "legacy" {
				c.credentialPublicReadVersion = 1
			}
			if mode == "activePrivateInput" {
				c.privateAdvance = &credentialAdvancePending{}
			}
			if mode == "lifecycle" {
				c.lifecycleInhibited = true
			}
			b.mu.Unlock()
			if mode == "private" || mode == "foreignProfile" || mode == "wrongDocument" || mode == "notPublic" {
				f.publicReadMode.Store(mode)
			}
			if _, e := f.g.WithVerifiedCredentialPublicRead(ctx, f.p, readTarget().Surface); e == nil {
				t.Fatal("unsafe selected read admitted", mode)
			}
			b.mu.Lock()
			retained := c.unknown["original-unknown"] && !c.executorQualified && !c.inventoryComplete && c.privacy != nil
			b.mu.Unlock()
			if !retained || f.mutations.Load() != 0 || f.acquireCalls.Load() != 0 {
				t.Fatal("failed read changed original authority")
			}
		})
	}
}
