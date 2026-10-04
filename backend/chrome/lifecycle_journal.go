package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"regexp"
	"sort"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
)

type LifecycleJournalChannel struct {
	ProfileChannel  string `json:"profileChannel"`
	BrowserInstance string `json:"browserInstance"`
}
type LifecycleJournalFence struct {
	BrokerEpoch  string `json:"brokerEpoch"`
	ChannelEpoch string `json:"channelEpoch"`
	ScopeHash    string `json:"scopeHash"`
}
type LifecycleJournalEnvelope struct {
	Version   int                             `json:"version"`
	Complete  bool                            `json:"complete"`
	Executors []data.ChromeRetirementManifest `json:"executors"`
}
type LifecycleJournalPreparation struct {
	TransitionID                         string
	Manifest                             LifecycleJournalEnvelope
	EnvelopeDigest, HostResolutionDigest string
}
type LifecycleJournalRecord struct {
	Version              int                       `json:"version"`
	Channel              LifecycleJournalChannel   `json:"channel"`
	TransitionID         string                    `json:"transitionId"`
	OldFence             LifecycleJournalFence     `json:"oldFence"`
	Phase                string                    `json:"phase"`
	Revision             int                       `json:"revision"`
	Manifest             *LifecycleJournalEnvelope `json:"manifest,omitempty"`
	EnvelopeDigest       string                    `json:"envelopeDigest,omitempty"`
	HostResolutionDigest string                    `json:"hostResolutionDigest,omitempty"`
	AdoptedFence         *LifecycleJournalFence    `json:"adoptedFence,omitempty"`
}
type LifecycleJournalStatus struct {
	Confirmed      bool                     `json:"confirmed"`
	Inhibited      bool                     `json:"inhibited"`
	NeedsAttention bool                     `json:"needsAttention"`
	Reason         string                   `json:"reason,omitempty"`
	Record         *LifecycleJournalRecord  `json:"record,omitempty"`
	History        []LifecycleJournalRecord `json:"history,omitempty"`
	StoreRevision  int                      `json:"storeRevision,omitempty"`
}

var journalOpaque = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var journalHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (g *LifecycleReceiptGuard) journalChannel() LifecycleJournalChannel {
	return LifecycleJournalChannel{g.inventory.ProfileChannel, g.inventory.BrowserInstance}
}
func (g *LifecycleReceiptGuard) journalFence() LifecycleJournalFence {
	return LifecycleJournalFence{g.inventory.BrokerEpoch, g.inventory.ChannelEpoch, g.inventory.ScopeHash}
}
func (g *LifecycleReceiptGuard) admitLifecycleCommand(c Command) bool {
	switch c.Action {
	case "retirement.intend", "retirement.prepare", "retirement.status":
		return c.Identity == (Identity{ProfileChannel: g.inventory.ProfileChannel, BrowserInstance: g.inventory.BrowserInstance}) && c.Locator == nil && c.ControlLease == nil && c.AttemptID == "" && c.FingerprintVersion == 0 && c.FingerprintSHA256 == ""
	case "executor.receipts", "executor.quiesce", "executor.retire", "record.stop":
		return g.pinned(c.Identity)
	}
	return false
}

// IntendJournal records private inhibition only; it grants no release authority.
func (g *LifecycleReceiptGuard) IntendJournal(ctx context.Context, p auth.Principal, transitionID string) (LifecycleJournalStatus, error) {
	if g == nil || !journalOpaque.MatchString(transitionID) {
		return LifecycleJournalStatus{}, ErrLifecycleReceiptAuthority
	}
	args := map[string]any{"channel": g.journalChannel(), "transitionId": transitionID, "oldFence": g.journalFence(), "expectedRevision": 0}
	return g.journalCall(ctx, p, "retirement.intend", args, transitionID, "intended", nil)
}

// PrepareJournal persists the already host-qualified proof without releasing epochs.
func (g *LifecycleReceiptGuard) PrepareJournal(ctx context.Context, p auth.Principal, preparation LifecycleJournalPreparation) (LifecycleJournalStatus, error) {
	if g == nil || !journalOpaque.MatchString(preparation.TransitionID) || !journalHash.MatchString(preparation.HostResolutionDigest) {
		return LifecycleJournalStatus{}, ErrLifecycleReceiptAuthority
	}
	canonical, err := canonicalJournalEnvelope(preparation.Manifest, g.journalChannel())
	if err != nil || data.ChromeRetirementDigest(canonical) != preparation.EnvelopeDigest {
		return LifecycleJournalStatus{}, ErrLifecycleReceiptAuthority
	}
	preparation.Manifest = canonical
	args := map[string]any{"channel": g.journalChannel(), "transitionId": preparation.TransitionID, "oldFence": g.journalFence(), "expectedRevision": 1, "manifest": canonical, "envelopeDigest": preparation.EnvelopeDigest, "hostResolutionDigest": preparation.HostResolutionDigest}
	return g.journalCall(ctx, p, "retirement.prepare", args, preparation.TransitionID, "prepared", &preparation)
}
func (g *LifecycleReceiptGuard) JournalStatus(ctx context.Context, p auth.Principal) (LifecycleJournalStatus, error) {
	if g == nil {
		return LifecycleJournalStatus{}, ErrLifecycleReceiptAuthority
	}
	return g.journalCall(ctx, p, "retirement.status", map[string]any{"profileChannel": g.inventory.ProfileChannel, "browserInstance": g.inventory.BrowserInstance}, "", "", nil)
}
func (g *LifecycleReceiptGuard) journalCall(ctx context.Context, p auth.Principal, action string, args map[string]any, transition, phase string, preparation *LifecycleJournalPreparation) (LifecycleJournalStatus, error) {
	request := newID()
	identity := Identity{ProfileChannel: g.inventory.ProfileChannel, BrowserInstance: g.inventory.BrowserInstance}
	raw, err := g.call(ctx, p, Command{RequestID: request, Action: action, Identity: identity, Args: args})
	if err != nil {
		return LifecycleJournalStatus{}, err
	}
	return decodeLifecycleJournal(raw, request, identity, g.journalFence(), transition, phase, preparation)
}
func strictJournalJSON(raw []byte, value any) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil {
		return false
	}
	return d.Decode(new(any)) == io.EOF
}
func canonicalJournalEnvelope(envelope LifecycleJournalEnvelope, channel LifecycleJournalChannel) (LifecycleJournalEnvelope, error) {
	if (envelope.Version != 1 && envelope.Version != 2) || !envelope.Complete || envelope.Executors == nil || len(envelope.Executors) > 64 {
		return LifecycleJournalEnvelope{}, ErrLifecycleReceiptAuthority
	}
	out := envelope
	out.Executors = make([]data.ChromeRetirementManifest, 0, len(envelope.Executors))
	seen := map[string]bool{}
	count := 0
	for _, m := range envelope.Executors {
		if m.Version != envelope.Version || m.Identity.ProfileChannel != channel.ProfileChannel || m.Identity.BrowserInstance != channel.BrowserInstance {
			return LifecycleJournalEnvelope{}, ErrLifecycleReceiptAuthority
		}
		raw, _, err := data.ChromeRetirementManifestJSON(m)
		if err != nil {
			return LifecycleJournalEnvelope{}, ErrLifecycleReceiptAuthority
		}
		var detached data.ChromeRetirementManifest
		if json.Unmarshal([]byte(raw), &detached) != nil {
			return LifecycleJournalEnvelope{}, ErrLifecycleReceiptAuthority
		}
		key := data.ChromeRetirementManifestID(m.Identity)
		if seen[key] {
			return LifecycleJournalEnvelope{}, ErrLifecycleReceiptAuthority
		}
		seen[key] = true
		count += len(m.Receipts)
		if count > 4096 {
			return LifecycleJournalEnvelope{}, ErrLifecycleReceiptAuthority
		}
		out.Executors = append(out.Executors, detached)
	}
	sort.Slice(out.Executors, func(i, j int) bool {
		a, b := out.Executors[i].Identity, out.Executors[j].Identity
		if a.TabID != b.TabID {
			return a.TabID < b.TabID
		}
		return a.DocumentID < b.DocumentID
	})
	return out, nil
}
func journalFenceValid(f LifecycleJournalFence) bool {
	return journalOpaque.MatchString(f.BrokerEpoch) && journalOpaque.MatchString(f.ChannelEpoch) && journalHash.MatchString(f.ScopeHash)
}
func journalRecordValid(r LifecycleJournalRecord, c LifecycleJournalChannel) bool {
	revision := data.ChromeRetirementPhaseRevision(r.Phase)
	if r.Version != 1 || r.Channel != c || !journalOpaque.MatchString(r.TransitionID) || !journalFenceValid(r.OldFence) || revision == 0 || r.Revision != revision {
		return false
	}
	if r.Phase == "intended" {
		return r.Manifest == nil && r.EnvelopeDigest == "" && r.HostResolutionDigest == "" && r.AdoptedFence == nil
	}
	if r.Manifest == nil || !journalHash.MatchString(r.EnvelopeDigest) || !journalHash.MatchString(r.HostResolutionDigest) {
		return false
	}
	canonical, err := canonicalJournalEnvelope(*r.Manifest, c)
	if err != nil || !reflect.DeepEqual(canonical, *r.Manifest) || data.ChromeRetirementDigest(canonical) != r.EnvelopeDigest {
		return false
	}
	if r.Phase == "adopted" {
		return r.AdoptedFence != nil && journalFenceValid(*r.AdoptedFence) && r.AdoptedFence.ScopeHash == r.OldFence.ScopeHash && r.AdoptedFence.BrokerEpoch != r.OldFence.BrokerEpoch && r.AdoptedFence.ChannelEpoch != r.OldFence.ChannelEpoch
	}
	return r.AdoptedFence == nil
}
func decodeLifecycleJournal(raw []byte, request string, identity Identity, fence LifecycleJournalFence, transition, phase string, preparation *LifecycleJournalPreparation) (LifecycleJournalStatus, error) {
	fail := func() (LifecycleJournalStatus, error) { return LifecycleJournalStatus{}, ErrLifecycleReceiptAuthority }
	if len(raw) > MaxFrameBytes {
		return fail()
	}
	var reply struct {
		RequestID  string          `json:"requestId"`
		Identity   Identity        `json:"identity"`
		Retirement json.RawMessage `json:"retirement"`
		Error      json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &reply) != nil || reply.RequestID != request || reply.Identity != identity || (len(reply.Error) > 0 && string(reply.Error) != "null") {
		return fail()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(reply.Retirement, &fields) != nil {
		return fail()
	}
	for _, key := range []string{"confirmed", "inhibited", "needsAttention"} {
		if _, ok := fields[key]; !ok {
			return fail()
		}
	}
	var status LifecycleJournalStatus
	if !strictJournalJSON(reply.Retirement, &status) || !status.Inhibited {
		return fail()
	}
	if !status.Confirmed {
		if phase != "" || !status.NeedsAttention || !journalOpaque.MatchString(status.Reason) || status.Record != nil || len(status.History) != 0 || status.StoreRevision != 0 {
			return fail()
		}
		return status, nil
	}
	for _, key := range []string{"record", "history", "storeRevision"} {
		if value, ok := fields[key]; !ok || string(value) == "null" {
			return fail()
		}
	}
	if status.NeedsAttention || status.Reason != "" || status.Record == nil || len(status.History) > 31 {
		return fail()
	}
	c := LifecycleJournalChannel{identity.ProfileChannel, identity.BrowserInstance}
	record := status.Record
	if !journalRecordValid(*record, c) || record.OldFence != fence || (transition != "" && record.TransitionID != transition) || (phase != "" && record.Phase != phase) {
		return fail()
	}
	total := record.Revision
	seen := map[string]bool{record.TransitionID: true}
	var prior *LifecycleJournalRecord
	for i := range status.History {
		h := &status.History[i]
		if !journalRecordValid(*h, c) || h.Phase != "adopted" || seen[h.TransitionID] || (prior != nil && *prior.AdoptedFence != h.OldFence) {
			return fail()
		}
		seen[h.TransitionID] = true
		total += h.Revision
		prior = h
	}
	if total != status.StoreRevision || (prior != nil && *prior.AdoptedFence != record.OldFence) {
		return fail()
	}
	if preparation != nil && (record.Manifest == nil || !reflect.DeepEqual(*record.Manifest, preparation.Manifest) || record.EnvelopeDigest != preparation.EnvelopeDigest || record.HostResolutionDigest != preparation.HostResolutionDigest) {
		return fail()
	}
	return status, nil
}
