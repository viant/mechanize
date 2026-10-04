package host

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"strings"
	"testing"
	"time"
)

func retirementAuthorityFixture(t *testing.T) (context.Context, data.ChromeRetirementAuthority) {
	t.Helper()
	p, _ := auth.NewPrincipal("fixture", "", "retirement-capability", []string{"desktop:control"})
	p.ClientID = "fixture-client"
	ctx, err := data.WithScope(auth.WithPrincipal(context.Background(), p), data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	hash := strings.Repeat("a", 64)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	a := data.ChromeRetirementAuthority{Namespace: p.Namespace, ClientID: p.ClientID, RequestID: "retire", ProfileChannel: "profile", BrowserInstance: "browser", TrustScope: "desktop", OldBrokerEpoch: "old-broker", OldChannelEpoch: "old-channel", OldScopeHash: hash, Phase: "prepared", PriorRevision: 1, GuardProof: "actual-admission-guard", CreatedAt: now, Now: now, Process: data.ChromeRetirementProcessEvidence{Version: 1, NativeHostPID: 20, NativeHostBirth: "1790000000:2", NativeHostImageDigest: hash, ChromePID: 10, ChromeBirth: "1790000000:1", ChromeImageDigest: hash, KernelPeerQualified: true, ImmediateParentQualified: true}, Policy: data.ChromeRetirementPolicyEvidence{Version: 1, ExtensionID: strings.Repeat("a", 32), TrustScope: "desktop", OriginScopeDigest: hash, NativeHostRequirementDigest: hash, ChromeRequirementDigest: hash, BrokerRequirementDigest: hash}, Proof: data.ChromeRetirementPhaseProof{Version: 1, InputInhibited: true, NoPending: true, NoUnknown: true, ExecutorsQuiescent: true, ReceiptCoverageComplete: true, RecordingHistoryRetained: true, BusinessLedgerReconciled: true, HostResolutionDigest: hash}, Manifests: []data.ChromeRetirementManifest{{Version: 1, Identity: data.ChromeRetirementDocumentIdentity{ProfileChannel: "profile", BrowserInstance: "browser", TabID: 7, FrameID: 0, DocumentID: "document"}, ReceiptRevision: 1, Receipts: []data.ChromeRetirementReceipt{{AttemptID: "browser-attempt", FingerprintSHA256: hash, DispatchState: "dispatched", EffectState: "unverified"}}, Readiness: data.ChromeRetirementReadiness{Quiesced: true, RecordingState: "none"}}}}
	a.TransitionID = data.ChromeRetirementID(a.Namespace, a.ClientID, a.ProfileChannel, a.BrowserInstance, a.RequestID)
	return ctx, a
}

func TestChromeRetirementInputRequiresHeldAuthority(t *testing.T) {
	if in, err := chromeRetirementInput(context.Background()); err == nil || in != nil {
		t.Fatal("untrusted request accepted")
	}
}
func TestChromeRetirementInputPreservesCanonicalVersion2History(t *testing.T) {
	ctx, a := retirementAuthorityFixture(t)
	a.Manifests[0].Version = 2
	a.Manifests[0].Receipts[0].FingerprintVersion = 2
	ctx, err := data.WithChromeRetirementAuthority(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := data.RequireChromeRetirementAuthority(ctx)
	if err != nil {
		t.Fatal(err)
	}
	in, err := chromeRetirementInput(ctx)
	if err != nil {
		t.Fatal(err)
	}
	row := in.WriteChromeRetirement[0]
	if *row.Revision != 1 || !row.Has.Revision || row.Has.AdoptionDigest || len(row.Manifests) != 1 || len(row.Audit) != 1 {
		t.Fatal("phase/presence changed")
	}
	m := row.Manifests[0]
	raw, digest, err := data.ChromeRetirementManifestJSON(canonical.Manifests[0])
	if err != nil {
		t.Fatal(err)
	}
	if *m.CanonicalManifestJson != raw || *m.ManifestDigest != digest || !m.Has.CanonicalManifestJson || *row.Audit[0].PayloadJson != canonical.AuditPayloadJSON {
		t.Fatal("canonical evidence changed")
	}
	var decoded data.ChromeRetirementManifest
	if err = json.Unmarshal([]byte(*m.CanonicalManifestJson), &decoded); err != nil || decoded.Version != 2 || decoded.Receipts[0].FingerprintVersion != 2 {
		t.Fatal("v2 metadata lost", err)
	}
	// A mismatched authenticated client must not reuse the captured capability.
	p, _ := auth.FromContext(ctx)
	p.ClientID = "another-client"
	if _, err = chromeRetirementInput(auth.WithPrincipal(ctx, p)); err == nil {
		t.Fatal("cross-client authority accepted")
	}
}
func TestChromeRetirementInputIntendedOmitsFutureEvidence(t *testing.T) {
	ctx, a := retirementAuthorityFixture(t)
	a.Phase = "intended"
	a.PriorRevision = 0
	a.Manifests = nil
	ctx, err := data.WithChromeRetirementAuthority(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	in, err := chromeRetirementInput(ctx)
	if err != nil {
		t.Fatal(err)
	}
	row := in.WriteChromeRetirement[0]
	if *row.Revision != 1 || row.Has.Manifests || row.Has.ManifestDigest || row.Has.AdoptionDigest || len(row.Audit) != 1 || *row.Audit[0].Sequence != 1 {
		t.Fatal("intended phase claimed future history")
	}
}
