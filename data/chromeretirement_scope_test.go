package data

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
)

func retirementAuthorityFixture(t *testing.T) (context.Context, ChromeRetirementAuthority) {
	t.Helper()
	p, _ := auth.NewPrincipal("fixture", "", "retirement-capability", []string{"desktop:control"})
	p.ClientID = "fixture-client"
	ctx, err := WithScope(auth.WithPrincipal(context.Background(), p), Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	hash := strings.Repeat("a", 64)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	a := ChromeRetirementAuthority{Namespace: p.Namespace, ClientID: p.ClientID, RequestID: "retire", ProfileChannel: "profile", BrowserInstance: "browser", TrustScope: "desktop", OldBrokerEpoch: "old-broker", OldChannelEpoch: "old-channel", OldScopeHash: hash, Phase: "prepared", PriorRevision: 1, GuardProof: "actual-admission-guard", CreatedAt: now, Now: now, Process: ChromeRetirementProcessEvidence{Version: 1, NativeHostPID: 20, NativeHostBirth: "1790000000:2", NativeHostImageDigest: hash, ChromePID: 10, ChromeBirth: "1790000000:1", ChromeImageDigest: hash, KernelPeerQualified: true, ImmediateParentQualified: true}, Policy: ChromeRetirementPolicyEvidence{Version: 1, ExtensionID: strings.Repeat("a", 32), TrustScope: "desktop", OriginScopeDigest: hash, NativeHostRequirementDigest: hash, ChromeRequirementDigest: hash, BrokerRequirementDigest: hash}, Proof: ChromeRetirementPhaseProof{Version: 1, InputInhibited: true, NoPending: true, NoUnknown: true, ExecutorsQuiescent: true, ReceiptCoverageComplete: true, RecordingHistoryRetained: true, BusinessLedgerReconciled: true, HostResolutionDigest: hash}, Manifests: []ChromeRetirementManifest{{Version: 1, Identity: ChromeRetirementDocumentIdentity{ProfileChannel: "profile", BrowserInstance: "browser", TabID: 7, FrameID: 0, DocumentID: "document"}, ReceiptRevision: 1, Receipts: []ChromeRetirementReceipt{{AttemptID: "browser-attempt", FingerprintSHA256: hash, DispatchState: "dispatched", EffectState: "unverified"}}, Readiness: ChromeRetirementReadiness{Quiesced: true, RecordingState: "none"}}}}
	a.TransitionID = ChromeRetirementID(a.Namespace, a.ClientID, a.ProfileChannel, a.BrowserInstance, a.RequestID)
	return ctx, a
}

func TestChromeRetirementCapabilityClosedHistoryAndPhaseProof(t *testing.T) {
	ctx, a := retirementAuthorityFixture(t)
	bound, err := WithChromeRetirementAuthority(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	got, err := RequireChromeRetirementAuthority(bound)
	if err != nil || got.ReceiptCount != 1 || got.ManifestCount != 1 {
		t.Fatalf("nonempty resolved history rejected: %+v %v", got, err)
	}
	a.Manifests[0].Receipts[0].AttemptID = "mutated-after-capability"
	detached, err := RequireChromeRetirementAuthority(bound)
	if err != nil || detached.Manifests[0].Receipts[0].AttemptID != "browser-attempt" {
		t.Fatal("caller changed issued capability")
	}
	for _, mode := range []string{"unknown receipt", "duplicate attempt", "raw error", "unretained recording", "active lease", "unquiesced", "foreign frame", "duplicate document", "forged client", "phase skip", "missing guard", "stale audit", "unreconciled business"} {
		t.Run(mode, func(t *testing.T) {
			ctx, a := retirementAuthorityFixture(t)
			switch mode {
			case "unknown receipt":
				a.Manifests[0].Receipts[0].DispatchState = "unknown"
			case "duplicate attempt":
				a.Manifests[0].Receipts = append(a.Manifests[0].Receipts, a.Manifests[0].Receipts[0])
				a.Manifests[0].ReceiptRevision = 2
			case "raw error":
				a.Manifests[0].Receipts[0].ErrorCode = "private-error-message"
			case "unretained recording":
				a.Manifests[0].Readiness.RecordingDroppedThrough = 1
			case "active lease":
				a.Manifests[0].Readiness.ControlLeaseHeld = true
			case "unquiesced":
				a.Manifests[0].Readiness.Quiesced = false
			case "foreign frame":
				a.Manifests[0].Identity.FrameID = 1
			case "duplicate document":
				a.Manifests = append(a.Manifests, a.Manifests[0])
			case "forged client":
				a.ClientID = "different"
			case "phase skip":
				a.PriorRevision = 0
			case "missing guard":
				a.GuardProof = ""
			case "stale audit":
				a.Now = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
			case "unreconciled business":
				a.Proof.BusinessLedgerReconciled = false
			}
			if _, err := WithChromeRetirementAuthority(ctx, a); err == nil {
				t.Fatal("unattested/unsafe retirement accepted")
			}
		})
	}
}
func TestChromeRetirementManifestStrictDecoderRejectsPrivateFields(t *testing.T) {
	_, a := retirementAuthorityFixture(t)
	raw, _, err := ChromeRetirementManifestJSON(a.Manifests[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeChromeRetirementManifest(raw); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	_ = json.Unmarshal([]byte(raw), &payload)
	for _, key := range []string{"value", "url", "fingerprint", "args", "errorMessage"} {
		payload[key] = "private-data"
		body, _ := json.Marshal(payload)
		if _, err := DecodeChromeRetirementManifest(string(body)); err == nil {
			t.Fatal("private manifest field retained")
		}
		delete(payload, key)
	}
	if _, err := DecodeChromeRetirementManifest(raw + "{}"); err == nil {
		t.Fatal("trailing manifest accepted")
	}
}
func TestChromeRetirementAdoptionRetainsChromeAndEnrollmentPolicy(t *testing.T) {
	for _, mode := range []string{"new native host", "new Chrome birth", "new Chrome PID", "new user UID", "new policy", "new scope"} {
		t.Run(mode, func(t *testing.T) {
			ctx, a := retirementAuthorityFixture(t)
			a.Phase = "adopted"
			a.PriorRevision = 3
			a.Proof.FenceReleaseConfirmed = true
			a.Adoption = &ChromeRetirementAdoptionEvidence{Version: 1, BrokerEpoch: "new-broker", ChannelEpoch: "new-channel", ScopeHash: a.OldScopeHash, Process: a.Process, Policy: a.Policy, FreshDocumentsQualified: true}
			switch mode {
			case "new native host":
				a.Adoption.Process.NativeHostPID = 30
				a.Adoption.Process.NativeHostBirth = "1790000000:3"
			case "new Chrome birth":
				a.Adoption.Process.ChromeBirth = "1790000000:3"
			case "new Chrome PID":
				a.Adoption.Process.ChromePID = 11
			case "new user UID":
				a.Adoption.Process.ChromeUID = 1
				a.Adoption.Process.NativeHostUID = 1
			case "new policy":
				a.Adoption.Policy.BrokerRequirementDigest = strings.Repeat("b", 64)
			case "new scope":
				a.Adoption.ScopeHash = strings.Repeat("b", 64)
			}
			_, err := WithChromeRetirementAuthority(ctx, a)
			if mode == "new native host" && err != nil {
				t.Fatal(err)
			}
			if mode != "new native host" && err == nil {
				t.Fatal("adoption migrated process/policy without original authorization")
			}
		})
	}
}

func TestChromeRetirementCrossLanguageCanonicalFixtures(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	for _, version := range []string{"v1", "v2"} {
		raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../testdata/chrome-retirement-canonical-"+version+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct {
			Version int `json:"version"`
			Cases   []struct {
				Name      string                   `json:"name"`
				Manifest  ChromeRetirementManifest `json:"manifest"`
				Canonical string                   `json:"canonical"`
				SHA256    string                   `json:"sha256"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(raw, &fixture); err != nil {
			t.Fatal(err)
		}
		for _, test := range fixture.Cases {
			t.Run(version+"/"+test.Name, func(t *testing.T) {
				raw, digest, err := ChromeRetirementManifestJSON(test.Manifest)
				if err != nil || raw != test.Canonical || digest != test.SHA256 {
					t.Fatalf("canonical mismatch: %s %s %v", raw, digest, err)
				}
			})
		}
	}
	if ChromeRetirementDigest(make(chan int)) != "" {
		t.Fatal("marshal error produced a hash")
	}
}

func TestChromeRetirementManifestExplicitFingerprintVersions(t *testing.T) {
	_, a := retirementAuthorityFixture(t)
	original := a.Manifests[0]
	for _, test := range []struct {
		name                            string
		manifestVersion, receiptVersion int
		valid                           bool
	}{
		{"legacyOmitted", 1, 0, true}, {"v2Explicit", 2, 2, true}, {"v2Missing", 2, 0, false}, {"v2Downgrade", 2, 1, false}, {"v2Unknown", 2, 3, false}, {"v1ClaimedV1", 1, 1, false}, {"v1ClaimedV2", 1, 2, false}, {"missingManifest", 0, 0, false}, {"unknownManifest", 3, 2, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := original
			m.Version = test.manifestVersion
			m.Receipts = append([]ChromeRetirementReceipt(nil), original.Receipts...)
			m.Receipts[0].FingerprintVersion = test.receiptVersion
			raw, _, err := ChromeRetirementManifestJSON(m)
			if (err == nil) != test.valid {
				t.Fatalf("version qualification differs: %v", err)
			}
			if test.valid {
				if _, err := DecodeChromeRetirementManifest(raw); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	raw, _, err := ChromeRetirementManifestJSON(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"0", "1", "2", "null"} {
		changed := strings.Replace(raw, `"fingerprintSHA256":`, `"fingerprintVersion":`+version+`,"fingerprintSHA256":`, 1)
		if _, err := DecodeChromeRetirementManifest(changed); err == nil {
			t.Fatalf("v1 explicit fingerprintVersion %s accepted", version)
		}
	}
}

func TestChromeRetirementAuthorityRejectsMixedManifestVersions(t *testing.T) {
	ctx, a := retirementAuthorityFixture(t)
	next := a.Manifests[0]
	next.Version = 2
	next.Identity.DocumentID = "v2-fresh-document"
	next.Receipts = append([]ChromeRetirementReceipt(nil), next.Receipts...)
	next.Receipts[0].AttemptID = "v2-fresh-attempt"
	next.Receipts[0].FingerprintVersion = 2
	a.Manifests = append(a.Manifests, next)
	if _, err := WithChromeRetirementAuthority(ctx, a); err == nil {
		t.Fatal("mixed current executor versions qualified")
	}
	a.Manifests = []ChromeRetirementManifest{next}
	bound, err := WithChromeRetirementAuthority(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	got, err := RequireChromeRetirementAuthority(bound)
	if err != nil || got.Manifests[0].Version != 2 || got.Manifests[0].Receipts[0].FingerprintVersion != 2 {
		t.Fatal("explicit v2 authority lost version", err)
	}
}

func TestChromeRetirementV2PreservesHistoryAndReadinessGates(t *testing.T) {
	for _, mode := range []string{"unknownDispatch", "unknownEffect", "activeLease", "activeRecording", "notQuiesced", "revisionMismatch", "subframe", "duplicate", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			_, a := retirementAuthorityFixture(t)
			m := a.Manifests[0]
			m.Version = 2
			m.Receipts[0].FingerprintVersion = 2
			switch mode {
			case "unknownDispatch":
				m.Receipts[0].DispatchState = "unknown"
			case "unknownEffect":
				m.Receipts[0].EffectState = "unknown"
			case "activeLease":
				m.Readiness.ControlLeaseHeld = true
			case "activeRecording":
				m.Readiness.RecordingState = "recording"
			case "notQuiesced":
				m.Readiness.Quiesced = false
			case "revisionMismatch":
				m.ReceiptRevision++
			case "subframe":
				m.Identity.FrameID = 1
			case "duplicate":
				m.Receipts = append(m.Receipts, m.Receipts[0])
				m.ReceiptRevision++
			case "overflow":
				m.Receipts = make([]ChromeRetirementReceipt, 513)
				m.ReceiptRevision = 513
			}
			if _, _, err := ChromeRetirementManifestJSON(m); err == nil {
				t.Fatal("v2 widened qualified history or readiness policy")
			}
		})
	}
}

func TestRetirementFreshObservationPreservesHistoricalPhaseTime(t *testing.T) {
	ctx, a := retirementAuthorityFixture(t)
	a.Now = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	a.CreatedAt = a.Now
	if _, err := WithChromeRetirementAuthority(ctx, a); err == nil {
		t.Fatal("stale evidence accepted without new observation")
	}
	a.EvidenceObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	bound, err := WithChromeRetirementAuthority(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	got, err := RequireChromeRetirementAuthority(bound)
	if err != nil {
		t.Fatal(err)
	}
	if got.Now != a.Now || got.CreatedAt != a.CreatedAt {
		t.Fatal("immutable phase time rewritten")
	}
	if strings.Contains(got.AuditPayloadJSON, "EvidenceObservedAt") || strings.Contains(got.AuditPayloadJSON, a.EvidenceObservedAt) {
		t.Fatal("fresh observation changed retained audit payload")
	}
	for _, stamp := range []string{time.Now().Add(-time.Minute).Format(time.RFC3339Nano), time.Now().Add(time.Hour).Format(time.RFC3339Nano), "invalid"} {
		a.EvidenceObservedAt = stamp
		if _, err := WithChromeRetirementAuthority(ctx, a); err == nil {
			t.Fatal("invalid observation accepted", stamp)
		}
	}
}
