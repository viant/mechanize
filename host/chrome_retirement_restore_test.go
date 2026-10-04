package host

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	get "github.com/viant/mechanize/data/chromeretirementget"
	"github.com/viant/mechanize/session"
)

func retirementRestoreFixture(t *testing.T, prepared bool) (auth.Principal, *get.Retirement, chrome.LifecycleReceiptInventory, data.ChromeRetirementAuthority) {
	t.Helper()
	ctx, a := retirementAuthorityFixture(t)
	p, _ := auth.FromContext(ctx)
	a.CreatedAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	a.Now = a.CreatedAt
	a.EvidenceObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	savedManifests, savedProof := a.Manifests, a.Proof
	a.Phase = "intended"
	a.PriorRevision = 0
	a.Manifests = nil
	a.Proof = data.ChromeRetirementPhaseProof{Version: 1, InputInhibited: true}
	bound, err := data.WithChromeRetirementAuthority(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	input, err := chromeRetirementInput(bound)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(input.WriteChromeRetirement[0])
	var row get.Retirement
	if json.Unmarshal(raw, &row) != nil {
		t.Fatal("convert generated row")
	}
	intendedAudit := row.Audit[0]
	if prepared {
		a.Phase = "prepared"
		a.PriorRevision = 1
		a.Manifests = savedManifests
		a.Proof = savedProof
		a.Now = time.Now().Add(-30 * time.Minute).UTC().Format(time.RFC3339Nano)
		bound, err = data.WithChromeRetirementAuthority(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		input, err = chromeRetirementInput(bound)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ = json.Marshal(input.WriteChromeRetirement[0])
		row = get.Retirement{}
		if json.Unmarshal(raw, &row) != nil {
			t.Fatal("convert generated prepared row")
		}
		*row.Revision = 2
		row.Audit = append(row.Audit, intendedAudit)
	}
	canonical, err := data.RequireChromeRetirementAuthority(bound)
	if err != nil {
		t.Fatal(err)
	}
	inventory := chrome.LifecycleReceiptInventory{GuardID: "fresh-live-guard", Owner: p.Namespace, ClientID: p.ClientID, ProfileChannel: a.ProfileChannel, BrowserInstance: a.BrowserInstance, BrokerEpoch: a.OldBrokerEpoch, ChannelEpoch: a.OldChannelEpoch, ScopeHash: a.OldScopeHash, TrustScope: a.TrustScope, Process: nativepeer.ChromeProcessEvidence{KernelPeerQualified: true, NativeHost: session.ProcessIdentity{PID: a.Process.NativeHostPID, UID: a.Process.NativeHostUID, StartToken: a.Process.NativeHostBirth}, ChromeParent: session.ProcessIdentity{PID: a.Process.ChromePID, UID: a.Process.ChromeUID, StartToken: a.Process.ChromeBirth}}}
	for _, m := range canonical.Manifests {
		i := m.Identity
		inventory.Roots = append(inventory.Roots, chrome.Identity{ProfileChannel: i.ProfileChannel, BrowserInstance: i.BrowserInstance, TabID: i.TabID, FrameID: i.FrameID, DocumentID: i.DocumentID, Generation: 1})
	}
	return p, &row, inventory, canonical
}
func TestRestoreChromeRetirementAuthority(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		p, row, inventory, original := retirementRestoreFixture(t, prepared)
		digest := ""
		if prepared {
			digest = original.Proof.HostResolutionDigest
		}
		restored, err := RestoreChromeRetirementAuthority(p, row, inventory, original.Process, original.Policy, digest)
		if err != nil {
			t.Fatalf("prepared=%v: %v", prepared, err)
		}
		if restored.EvidenceObservedAt == original.EvidenceObservedAt {
			t.Fatal("guard observation not refreshed")
		}
		restored.EvidenceObservedAt = original.EvidenceObservedAt
		if !reflect.DeepEqual(restored, original) {
			t.Fatalf("retained authority changed\noriginal=%+v\nrestored=%+v", original, restored)
		}
	}
}
func TestRestoreChromeRetirementRejectsConflicts(t *testing.T) {
	cases := map[string]func(*get.Retirement, *chrome.LifecycleReceiptInventory, *data.ChromeRetirementAuthority, *string){
		"foreign inventory": func(_ *get.Retirement, i *chrome.LifecycleReceiptInventory, _ *data.ChromeRetirementAuthority, _ *string) {
			i.ClientID = "other"
		},
		"foreign row": func(r *get.Retirement, _ *chrome.LifecycleReceiptInventory, _ *data.ChromeRetirementAuthority, _ *string) {
			r.ClientId = retirementValue("other")
		},
		"changed live fence": func(_ *get.Retirement, i *chrome.LifecycleReceiptInventory, _ *data.ChromeRetirementAuthority, _ *string) {
			i.ChannelEpoch = "other"
		},
		"changed process": func(_ *get.Retirement, _ *chrome.LifecycleReceiptInventory, a *data.ChromeRetirementAuthority, _ *string) {
			a.Process.ChromeImageDigest = a.Process.ChromeImageDigest[:63] + "b"
		},
		"missing matcher": func(_ *get.Retirement, _ *chrome.LifecycleReceiptInventory, _ *data.ChromeRetirementAuthority, d *string) {
			*d = ""
		},
		"wrong matcher": func(_ *get.Retirement, _ *chrome.LifecycleReceiptInventory, _ *data.ChromeRetirementAuthority, d *string) {
			*d = (*d)[:63] + "b"
		},
		"duplicate audit": func(r *get.Retirement, _ *chrome.LifecycleReceiptInventory, _ *data.ChromeRetirementAuthority, _ *string) {
			r.Audit[1] = r.Audit[0]
		},
		"extra audit": func(r *get.Retirement, _ *chrome.LifecycleReceiptInventory, _ *data.ChromeRetirementAuthority, _ *string) {
			r.Audit = append(r.Audit, r.Audit[0])
		},
		"unknown audit field": func(r *get.Retirement, _ *chrome.LifecycleReceiptInventory, _ *data.ChromeRetirementAuthority, _ *string) {
			v := *r.Audit[0].PayloadJson
			v = v[:len(v)-1] + `,"extra":true}`
			r.Audit[0].PayloadJson = &v
		},
		"wrong audit time": func(r *get.Retirement, _ *chrome.LifecycleReceiptInventory, _ *data.ChromeRetirementAuthority, _ *string) {
			r.Audit[0].CreatedAt = r.CreatedAt
		},
		"wrong manifest": func(r *get.Retirement, _ *chrome.LifecycleReceiptInventory, _ *data.ChromeRetirementAuthority, _ *string) {
			r.Manifests[0].ReceiptCount = retirementValue(999)
		},
		"released": func(r *get.Retirement, _ *chrome.LifecycleReceiptInventory, _ *data.ChromeRetirementAuthority, _ *string) {
			r.Phase = retirementValue("released")
		},
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			p, row, inventory, a := retirementRestoreFixture(t, true)
			digest := a.Proof.HostResolutionDigest
			alter(row, &inventory, &a, &digest)
			if _, err := RestoreChromeRetirementAuthority(p, row, inventory, a.Process, a.Policy, digest); err == nil {
				t.Fatal("accepted inconsistent retained context")
			}
		})
	}
}
