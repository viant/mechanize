package chrome

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/viant/mechanize/data"
)

func TestLifecycleJournalChannelAdmission(t *testing.T) {
	g := &LifecycleReceiptGuard{inventory: LifecycleReceiptInventory{ProfileChannel: "profile", BrowserInstance: "browser"}}
	identity := Identity{ProfileChannel: "profile", BrowserInstance: "browser"}
	for _, action := range []string{"retirement.intend", "retirement.prepare", "retirement.status"} {
		c := Command{Action: action, Identity: identity}
		if !g.admitLifecycleCommand(c) {
			t.Fatal("empty inventory journal rejected")
		}
		variants := []Command{c, c, c, c, c, c}
		variants[0].Identity.DocumentID = "doc"
		variants[1].Identity.Generation = 1
		variants[2].Identity.TabID = 1
		variants[3].Locator = &Locator{}
		variants[4].ControlLease = &Lease{}
		variants[5].AttemptID = "attempt"
		for _, v := range variants {
			if g.admitLifecycleCommand(v) {
				t.Fatal("journal accepted document or dispatch metadata")
			}
		}
	}
	for _, action := range []string{"executor.receipts", "executor.quiesce", "retirement.release", "retirement.adopt", "element.press"} {
		if g.admitLifecycleCommand(Command{Action: action, Identity: identity}) {
			t.Fatal("channel identity admitted unsupported action", action)
		}
	}
}
func journalTestReply(t *testing.T, identity Identity, status LifecycleJournalStatus) []byte {
	t.Helper()
	statusRaw, _ := json.Marshal(status)
	var result map[string]any
	_ = json.Unmarshal(statusRaw, &result)
	if status.Confirmed && len(status.History) == 0 {
		result["history"] = []any{}
	}
	raw, err := json.Marshal(map[string]any{"requestId": "request", "identity": identity, "retirement": result})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestLifecycleJournalIntended(t *testing.T) {
	identity := Identity{ProfileChannel: "profile", BrowserInstance: "browser"}
	fence := LifecycleJournalFence{"broker", "channel", strings.Repeat("a", 64)}
	status := LifecycleJournalStatus{Confirmed: true, Inhibited: true, Record: &LifecycleJournalRecord{Version: 1, Channel: LifecycleJournalChannel{"profile", "browser"}, TransitionID: "transition", OldFence: fence, Phase: "intended", Revision: 1}, StoreRevision: 1}
	decode := func(s LifecycleJournalStatus) error {
		_, err := decodeLifecycleJournal(journalTestReply(t, identity, s), "request", identity, fence, "transition", "intended", nil)
		return err
	}
	if err := decode(status); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*LifecycleJournalStatus){func(s *LifecycleJournalStatus) { s.Inhibited = false }, func(s *LifecycleJournalStatus) { s.Confirmed = false }, func(s *LifecycleJournalStatus) { s.NeedsAttention = true }, func(s *LifecycleJournalStatus) { s.Record.TransitionID = "other" }, func(s *LifecycleJournalStatus) { s.Record.OldFence.BrokerEpoch = "other" }, func(s *LifecycleJournalStatus) { s.Record.Phase = "released" }, func(s *LifecycleJournalStatus) { s.StoreRevision = 2 }} {
		copy := status
		record := *status.Record
		copy.Record = &record
		alter(&copy)
		if decode(copy) == nil {
			t.Fatal("accepted conflicting journal acknowledgement")
		}
	}
	if _, err := decodeLifecycleJournal(journalTestReply(t, identity, status), "different", identity, fence, "transition", "intended", nil); err == nil {
		t.Fatal("accepted wrong request")
	}
	status = LifecycleJournalStatus{Inhibited: true, NeedsAttention: true, Reason: "retirementNotFound"}
	if result, err := decodeLifecycleJournal(journalTestReply(t, identity, status), "request", identity, fence, "", "", nil); err != nil || result.Confirmed {
		t.Fatal("invalid missing journal status", err)
	}
}
func TestLifecycleJournalPrepared(t *testing.T) {
	identity := Identity{ProfileChannel: "profile", BrowserInstance: "browser"}
	channel := LifecycleJournalChannel{"profile", "browser"}
	fence := LifecycleJournalFence{"broker", "channel", strings.Repeat("a", 64)}
	envelope := LifecycleJournalEnvelope{Version: 2, Complete: true, Executors: []data.ChromeRetirementManifest{}}
	canonical, err := canonicalJournalEnvelope(envelope, channel)
	if err != nil {
		t.Fatal(err)
	}
	prep := LifecycleJournalPreparation{TransitionID: "transition", Manifest: canonical, EnvelopeDigest: data.ChromeRetirementDigest(canonical), HostResolutionDigest: strings.Repeat("b", 64)}
	status := LifecycleJournalStatus{Confirmed: true, Inhibited: true, Record: &LifecycleJournalRecord{Version: 1, Channel: channel, TransitionID: "transition", OldFence: fence, Phase: "prepared", Revision: 2, Manifest: &canonical, EnvelopeDigest: prep.EnvelopeDigest, HostResolutionDigest: prep.HostResolutionDigest}, StoreRevision: 2}
	decode := func() error {
		_, err := decodeLifecycleJournal(journalTestReply(t, identity, status), "request", identity, fence, "transition", "prepared", &prep)
		return err
	}
	if err := decode(); err != nil {
		t.Fatal(err)
	}
	status.Record.HostResolutionDigest = strings.Repeat("c", 64)
	if decode() == nil {
		t.Fatal("accepted changed host resolution")
	}
	status.Record.HostResolutionDigest = prep.HostResolutionDigest
	status.Record.EnvelopeDigest = strings.Repeat("d", 64)
	if decode() == nil {
		t.Fatal("accepted changed envelope")
	}
	for _, bad := range []LifecycleJournalEnvelope{{Version: 2, Complete: true}, {Version: 2, Executors: []data.ChromeRetirementManifest{}}, {Version: 3, Complete: true, Executors: []data.ChromeRetirementManifest{}}} {
		if _, err := canonicalJournalEnvelope(bad, channel); err == nil {
			t.Fatal("accepted incomplete envelope")
		}
	}
}
