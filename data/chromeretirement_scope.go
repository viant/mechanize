package data

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

type ChromeRetirementProcessEvidence struct {
	Version                  int    `json:"version"`
	NativeHostPID            int    `json:"nativeHostPid"`
	NativeHostUID            uint32 `json:"nativeHostUid"`
	NativeHostBirth          string `json:"nativeHostBirth"`
	NativeHostImageDigest    string `json:"nativeHostImageDigest"`
	ChromePID                int    `json:"chromePid"`
	ChromeUID                uint32 `json:"chromeUid"`
	ChromeBirth              string `json:"chromeBirth"`
	ChromeImageDigest        string `json:"chromeImageDigest"`
	KernelPeerQualified      bool   `json:"kernelPeerQualified"`
	ImmediateParentQualified bool   `json:"immediateParentQualified"`
}
type ChromeRetirementPolicyEvidence struct {
	Version                     int    `json:"version"`
	ExtensionID                 string `json:"extensionId"`
	TrustScope                  string `json:"trustScope"`
	OriginScopeDigest           string `json:"originScopeDigest"`
	NativeHostRequirementDigest string `json:"nativeHostRequirementDigest"`
	ChromeRequirementDigest     string `json:"chromeRequirementDigest"`
	BrokerRequirementDigest     string `json:"brokerRequirementDigest"`
	ProfileQualified            bool   `json:"profileQualified"`
	ProfileScopeDigest          string `json:"profileScopeDigest,omitempty"`
}
type ChromeRetirementDocumentIdentity struct {
	ProfileChannel  string `json:"profileChannel"`
	BrowserInstance string `json:"browserInstance"`
	TabID           int    `json:"tabId"`
	FrameID         int    `json:"frameId"`
	DocumentID      string `json:"documentId"`
}

// BrowserAttemptID is retained opaque browser history. It is not the durable
// attempt ID; the host must separately prove the run/plan/step correspondence.
type ChromeRetirementReceipt struct {
	AttemptID         string `json:"attemptId"`
	FingerprintSHA256 string `json:"fingerprintSHA256"`
	// Zero is the legacy omitted field; v2 must explicitly qualify version 2.
	FingerprintVersion int    `json:"fingerprintVersion,omitempty"`
	DispatchState      string `json:"dispatchState"`
	EffectState        string `json:"effectState"`
	ErrorCode          string `json:"errorCode,omitempty"`
	ErrorDispatchState string `json:"errorDispatchState,omitempty"`
}
type ChromeRetirementReadiness struct {
	Quiesced                    bool   `json:"quiesced"`
	ControlLeaseHeld            bool   `json:"controlLeaseHeld"`
	RecordingState              string `json:"recordingState"`
	RecordingLastSequence       int64  `json:"recordingLastSequence"`
	RecordingDroppedThrough     int64  `json:"recordingDroppedThrough"`
	RecordingLeaseExpiresUnixMs int64  `json:"recordingLeaseExpiresUnixMs"`
}
type ChromeRetirementManifest struct {
	Version         int                              `json:"version"`
	Identity        ChromeRetirementDocumentIdentity `json:"identity"`
	ReceiptRevision int64                            `json:"receiptRevision"`
	Receipts        []ChromeRetirementReceipt        `json:"receipts"`
	Readiness       ChromeRetirementReadiness        `json:"readiness"`
}
type ChromeRetirementPhaseProof struct {
	HostResolutionDigest     string `json:"hostResolutionDigest,omitempty"`
	Version                  int    `json:"version"`
	InputInhibited           bool   `json:"inputInhibited"`
	NoPending                bool   `json:"noPending"`
	NoUnknown                bool   `json:"noUnknown"`
	ExecutorsQuiescent       bool   `json:"executorsQuiescent"`
	ReceiptCoverageComplete  bool   `json:"receiptCoverageComplete"`
	RecordingHistoryRetained bool   `json:"recordingHistoryRetained"`
	BusinessLedgerReconciled bool   `json:"businessLedgerReconciled"`
	FenceReleaseConfirmed    bool   `json:"fenceReleaseConfirmed"`
}

// The first ledger slice permits same-policy broker/native-host restart while
// retaining the exact Chrome parent. It does not authorize upgraded code pins:
// that requires immutable intended-phase successor-policy authorization before
// release, not a relaxed adoption comparison.
type ChromeRetirementAdoptionEvidence struct {
	Version                 int                             `json:"version"`
	BrokerEpoch             string                          `json:"brokerEpoch"`
	ChannelEpoch            string                          `json:"channelEpoch"`
	ScopeHash               string                          `json:"scopeHash"`
	Process                 ChromeRetirementProcessEvidence `json:"process"`
	Policy                  ChromeRetirementPolicyEvidence  `json:"policy"`
	FreshDocumentsQualified bool                            `json:"freshDocumentsQualified"`
}

// This capability is issued only by trusted host lifecycle code while admission
// is inhibited and actual peer/receipt/business-ledger proofs are held. No wire
// body, manifest or claimed boolean can construct the private context value.
type ChromeRetirementAuthority struct {
	// EvidenceObservedAt is the fresh host guard observation, independent of the
	// immutable phase timestamp Now. Empty retains the original Now freshness rule.
	// Only trusted lifecycle code may refresh it after revalidating the old channel.
	EvidenceObservedAt string

	Namespace, ClientID, TransitionID, RequestID, ProfileChannel, BrowserInstance         string
	TrustScope, OldBrokerEpoch, OldChannelEpoch, OldScopeHash                             string
	Phase, GuardProof, CreatedAt, Now                                                     string
	PriorRevision                                                                         int
	Process                                                                               ChromeRetirementProcessEvidence
	Policy                                                                                ChromeRetirementPolicyEvidence
	Proof                                                                                 ChromeRetirementPhaseProof
	Manifests                                                                             []ChromeRetirementManifest
	Adoption                                                                              *ChromeRetirementAdoptionEvidence
	ProcessJSON, PolicyJSON, EvidenceDigest, ManifestDigest, AdoptionJSON, AdoptionDigest string
	ManifestCount, ReceiptCount                                                           int
	AuditID, AuditPayloadJSON                                                             string
}
type chromeRetirementAuthorityKey struct{}

var retirementOpaque = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var retirementHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var retirementExtension = regexp.MustCompile(`^[a-p]{32}$`)

func ChromeRetirementDigest(value any) string {
	raw, err := canonicalChromeRetirementJSON(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func canonicalChromeRetirementJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(normalized); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(out.String(), "\n")), nil
}

func ChromeRetirementID(namespace, client, channel, browser, request string) string {
	return ChromeRetirementDigest([]string{"chrome-retirement-v1", namespace, client, channel, browser, request})
}
func ChromeRetirementManifestID(identity ChromeRetirementDocumentIdentity) string {
	return ChromeRetirementDigest(identity)
}
func ChromeRetirementPhaseRevision(phase string) int {
	switch phase {
	case "intended":
		return 1
	case "prepared":
		return 2
	case "released":
		return 3
	case "adopted":
		return 4
	}
	return 0
}
func ChromeRetirementPreviousPhase(phase string) string {
	switch phase {
	case "prepared":
		return "intended"
	case "released":
		return "prepared"
	case "adopted":
		return "released"
	}
	return ""
}

func validateRetirementProcess(p ChromeRetirementProcessEvidence) error {
	if p.Version != 1 || p.NativeHostPID <= 0 || p.NativeHostPID > 2147483647 || p.ChromePID <= 0 || p.ChromePID > 2147483647 || p.ChromePID == p.NativeHostPID || p.NativeHostUID != p.ChromeUID || !model.ValidProcessStartToken(p.NativeHostBirth) || !model.ValidProcessStartToken(p.ChromeBirth) || !retirementHash.MatchString(p.NativeHostImageDigest) || !retirementHash.MatchString(p.ChromeImageDigest) || !p.KernelPeerQualified || !p.ImmediateParentQualified {
		return errors.New("qualified sanitized Chrome process evidence required")
	}
	return nil
}
func validateRetirementPolicy(p ChromeRetirementPolicyEvidence) error {
	if p.Version != 1 || !retirementExtension.MatchString(p.ExtensionID) || !retirementHash.MatchString(p.OriginScopeDigest) || !retirementHash.MatchString(p.NativeHostRequirementDigest) || !retirementHash.MatchString(p.ChromeRequirementDigest) || !retirementHash.MatchString(p.BrokerRequirementDigest) {
		return errors.New("bounded sanitized Chrome policy evidence required")
	}
	if p.TrustScope == "profile" {
		if !p.ProfileQualified || !retirementHash.MatchString(p.ProfileScopeDigest) {
			return errors.New("actual profile qualification required")
		}
	} else if p.TrustScope != "desktop" || p.ProfileQualified || p.ProfileScopeDigest != "" {
		return errors.New("honest explicit Chrome trust scope required")
	}
	return nil
}
func ChromeRetirementManifestJSON(m ChromeRetirementManifest) (string, string, error) {
	if (m.Version != 1 && m.Version != 2) || !retirementOpaque.MatchString(m.Identity.ProfileChannel) || !retirementOpaque.MatchString(m.Identity.BrowserInstance) || !retirementOpaque.MatchString(m.Identity.DocumentID) || m.Identity.TabID <= 0 || m.Identity.TabID > 2147483647 || m.Identity.FrameID != 0 || m.ReceiptRevision < 0 || m.ReceiptRevision > 9007199254740991 || len(m.Receipts) > 512 {
		return "", "", errors.New("bounded exact root receipt manifest required")
	}
	r := m.Readiness
	if !r.Quiesced || r.ControlLeaseHeld || (r.RecordingState != "none" && r.RecordingState != "stopped") || r.RecordingLastSequence < 0 || r.RecordingLastSequence > 9007199254740991 || r.RecordingDroppedThrough != 0 || r.RecordingLeaseExpiresUnixMs != 0 {
		return "", "", errors.New("quiescent fully retained recording and renderer history required")
	}
	if m.ReceiptRevision != int64(len(m.Receipts)) {
		return "", "", errors.New("complete non-evicting receipt revision required")
	}
	m.Receipts = append(make([]ChromeRetirementReceipt, 0, len(m.Receipts)), m.Receipts...)
	seen := map[string]bool{}
	for _, r := range m.Receipts {
		if m.Version == 1 && r.FingerprintVersion != 0 || m.Version == 2 && r.FingerprintVersion != 2 {
			return "", "", errors.New("receipt fingerprint version must match explicit manifest version")
		}
		if (r.ErrorCode == "") != (r.ErrorDispatchState == "") {
			return "", "", errors.New("paired sanitized error classification required")
		}
		if !retirementOpaque.MatchString(r.AttemptID) || seen[r.AttemptID] || !retirementHash.MatchString(r.FingerprintSHA256) || (r.DispatchState != "dispatched" && r.DispatchState != "notDispatched") || (r.EffectState != "none" && r.EffectState != "unverified" && r.EffectState != "verified") || (r.ErrorDispatchState != "" && r.ErrorDispatchState != "dispatched" && r.ErrorDispatchState != "notDispatched") {
			return "", "", errors.New("unique bounded resolved receipt history required")
		}
		if r.ErrorCode != "" && r.ErrorCode != "unclassified" && !retirementOpaque.MatchString(r.ErrorCode) {
			return "", "", errors.New("sanitized receipt error classification required")
		}
		// Only closed classifications survive; raw or unrecognized diagnostics
		// are represented as unclassified, never retained verbatim.
		if r.ErrorCode != "" && !retirementReceiptErrors[r.ErrorCode] {
			return "", "", errors.New("unrecognized receipt classification must be unclassified")
		}
		seen[r.AttemptID] = true
	}
	sort.Slice(m.Receipts, func(i, j int) bool { return m.Receipts[i].AttemptID < m.Receipts[j].AttemptID })
	raw, err := canonicalChromeRetirementJSON(m)
	if err != nil || len(raw) > 262144 {
		return "", "", errors.New("bounded canonical manifest required")
	}
	return string(raw), ChromeRetirementDigest(m), nil
}

var retirementReceiptErrors = map[string]bool{"unclassified": true, "ambiguousTarget": true, "coverageIncomplete": true, "invalidLocator": true, "invalidRequest": true, "targetNotActionable": true, "targetNotFound": true, "unsupportedAction": true, "unsupportedAttribute": true, "unsupportedControl": true, "unsupportedSelector": true, "userActivationRequired": true, "dispatchFailure": true}

func canonicalRetirementAuthority(ctx context.Context, a ChromeRetirementAuthority) (ChromeRetirementAuthority, error) {
	p, err := auth.FromContext(ctx)
	if err != nil || p.Namespace != a.Namespace || p.ClientID != a.ClientID || !p.HasScope("desktop:control") {
		return a, auth.ErrUnauthorized
	}
	if _, err := RequireScope(ctx, a.Namespace); err != nil {
		return a, err
	}
	for _, id := range []string{a.ClientID, a.RequestID, a.ProfileChannel, a.BrowserInstance, a.OldBrokerEpoch, a.OldChannelEpoch, a.OldScopeHash, a.GuardProof} {
		if !retirementOpaque.MatchString(id) {
			return a, errors.New("bounded exact retirement correlation required")
		}
	}
	if a.TransitionID != ChromeRetirementID(a.Namespace, a.ClientID, a.ProfileChannel, a.BrowserInstance, a.RequestID) || ChromeRetirementPhaseRevision(a.Phase) != a.PriorRevision+1 || a.PriorRevision < 0 || a.PriorRevision > 3 {
		return a, errors.New("exact sequential retirement revision required")
	}
	observedText := a.EvidenceObservedAt
	if observedText == "" {
		observedText = a.Now
	}
	observed, err := time.Parse(time.RFC3339Nano, observedText)
	if err != nil || observed.After(time.Now().Add(time.Second)) || time.Since(observed) > 30*time.Second {
		return a, errors.New("fresh retirement guard observation required")
	}
	at, err := time.Parse(time.RFC3339Nano, a.Now)
	if err != nil || at.After(time.Now().Add(time.Second)) {
		return a, errors.New("future retirement phase timestamp rejected")
	}
	created, err := time.Parse(time.RFC3339Nano, a.CreatedAt)
	if err != nil || created.After(at) || a.Phase == "intended" && a.CreatedAt != a.Now {
		return a, errors.New("immutable retirement creation time required")
	}
	if err := validateRetirementProcess(a.Process); err != nil {
		return a, err
	}
	if err := validateRetirementPolicy(a.Policy); err != nil {
		return a, err
	}
	if a.TrustScope != a.Policy.TrustScope {
		return a, errors.New("retirement policy scope mismatch")
	}
	a.ProcessJSON = string(mustRetirementJSON(a.Process))
	a.PolicyJSON = string(mustRetirementJSON(a.Policy))
	a.EvidenceDigest = ChromeRetirementDigest([]json.RawMessage{json.RawMessage(a.ProcessJSON), json.RawMessage(a.PolicyJSON)})
	if a.Proof.Version != 1 || !a.Proof.InputInhibited {
		return a, errors.New("trusted inhibited retirement phase proof required")
	}
	a.ManifestCount, a.ReceiptCount = 0, 0
	a.ManifestDigest = ""
	if a.Phase == "intended" {
		if len(a.Manifests) != 0 || a.Adoption != nil {
			return a, errors.New("intended retirement cannot claim exported or adopted history")
		}
	} else {
		if !a.Proof.NoPending || !a.Proof.NoUnknown || !a.Proof.ExecutorsQuiescent || !a.Proof.ReceiptCoverageComplete || !a.Proof.RecordingHistoryRetained || !a.Proof.BusinessLedgerReconciled || !retirementHash.MatchString(a.Proof.HostResolutionDigest) || len(a.Manifests) > 64 {
			return a, errors.New("complete trusted reconciled retirement proof required")
		}
		total := 0
		seen := map[string]bool{}
		digests := []string{}
		a.Manifests = append([]ChromeRetirementManifest(nil), a.Manifests...)
		for i, m := range a.Manifests {
			if i > 0 && m.Version != a.Manifests[0].Version {
				return a, errors.New("mixed retirement manifest versions are not qualified")
			}
			if m.Identity.ProfileChannel != a.ProfileChannel || m.Identity.BrowserInstance != a.BrowserInstance {
				return a, errors.New("foreign manifest channel")
			}
			raw, digest, err := ChromeRetirementManifestJSON(m)
			if err != nil {
				return a, err
			}
			id := ChromeRetirementManifestID(m.Identity)
			if seen[id] {
				return a, errors.New("duplicate retirement document")
			}
			seen[id] = true
			total += len(raw)
			a.ReceiptCount += len(m.Receipts)
			if total > 2*1024*1024 || a.ReceiptCount > 4096 {
				return a, errors.New("aggregate retirement history exceeds explicit qualification bound")
			}
			_ = json.Unmarshal([]byte(raw), &a.Manifests[i])
			digests = append(digests, digest)
		}
		sort.Slice(a.Manifests, func(i, j int) bool {
			return ChromeRetirementManifestID(a.Manifests[i].Identity) < ChromeRetirementManifestID(a.Manifests[j].Identity)
		})
		sort.Strings(digests)
		a.ManifestCount = len(a.Manifests)
		a.ManifestDigest = ChromeRetirementDigest(digests)
		if (a.Phase == "released" || a.Phase == "adopted") && !a.Proof.FenceReleaseConfirmed {
			return a, errors.New("exact release acknowledgement required")
		}
	}
	a.AdoptionJSON, a.AdoptionDigest = "", ""
	if a.Phase == "adopted" {
		if a.Adoption == nil || a.Adoption.Version != 1 || !a.Adoption.FreshDocumentsQualified || !retirementOpaque.MatchString(a.Adoption.BrokerEpoch) || !retirementOpaque.MatchString(a.Adoption.ChannelEpoch) || !retirementOpaque.MatchString(a.Adoption.ScopeHash) || a.Adoption.BrokerEpoch == a.OldBrokerEpoch && a.Adoption.ChannelEpoch == a.OldChannelEpoch {
			return a, errors.New("fresh independently qualified adoption required")
		}
		if err := validateRetirementProcess(a.Adoption.Process); err != nil {
			return a, err
		}
		if a.Adoption.Process.ChromePID != a.Process.ChromePID || a.Adoption.Process.ChromeUID != a.Process.ChromeUID || a.Adoption.Process.ChromeBirth != a.Process.ChromeBirth || a.Adoption.Process.ChromeImageDigest != a.Process.ChromeImageDigest {
			return a, errors.New("same-policy restart must retain exact original Chrome process")
		}
		if err := validateRetirementPolicy(a.Adoption.Policy); err != nil {
			return a, err
		}
		if a.Adoption.Policy != a.Policy || a.Adoption.ScopeHash != a.OldScopeHash {
			return a, errors.New("adoption cannot migrate enrollment policy")
		}
		a.AdoptionJSON = string(mustRetirementJSON(a.Adoption))
		a.AdoptionDigest = ChromeRetirementDigest(a.Adoption)
	} else if a.Adoption != nil {
		return a, errors.New("adoption evidence belongs only to adopted phase")
	}
	a.AuditID = ChromeRetirementDigest([]string{"retirement-audit", a.Namespace, a.TransitionID, a.Phase})
	a.AuditPayloadJSON = string(mustRetirementJSON(struct {
		Version        int                        `json:"version"`
		TransitionID   string                     `json:"transitionId"`
		RequestID      string                     `json:"requestId"`
		Phase          string                     `json:"phase"`
		PriorRevision  int                        `json:"priorRevision"`
		GuardProof     string                     `json:"guardProof"`
		EvidenceDigest string                     `json:"evidenceDigest"`
		ManifestDigest string                     `json:"manifestDigest,omitempty"`
		AdoptionDigest string                     `json:"adoptionDigest,omitempty"`
		Proof          ChromeRetirementPhaseProof `json:"proof"`
	}{1, a.TransitionID, a.RequestID, a.Phase, a.PriorRevision, a.GuardProof, a.EvidenceDigest, a.ManifestDigest, a.AdoptionDigest, a.Proof}))
	return a, ctx.Err()
}
func mustRetirementJSON(value any) []byte { raw, _ := json.Marshal(value); return raw }
func WithChromeRetirementAuthority(ctx context.Context, a ChromeRetirementAuthority) (context.Context, error) {
	a, err := canonicalRetirementAuthority(ctx, a)
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, chromeRetirementAuthorityKey{}, string(mustRetirementJSON(a))), nil
}
func RequireChromeRetirementAuthority(ctx context.Context) (ChromeRetirementAuthority, error) {
	raw, ok := ctx.Value(chromeRetirementAuthorityKey{}).(string)
	if !ok {
		return ChromeRetirementAuthority{}, errors.New("trusted retirement lifecycle authority required")
	}
	var a ChromeRetirementAuthority
	if json.Unmarshal([]byte(raw), &a) != nil {
		return a, errors.New("invalid retirement lifecycle authority")
	}
	return canonicalRetirementAuthority(ctx, a)
}

// Strict decoding prevents extra raw values, diagnostics, URLs or trailing
// payloads from being smuggled into the retained sanitized manifest.
func DecodeChromeRetirementManifest(raw string) (ChromeRetirementManifest, error) {
	var m ChromeRetirementManifest
	if len(raw) > 262144 {
		return m, errors.New("manifest size exceeds bound")
	}
	d := json.NewDecoder(bytes.NewBufferString(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil {
		return m, errors.New("closed sanitized manifest required")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return m, errors.New("trailing manifest data")
	}
	canonical, _, err := ChromeRetirementManifestJSON(m)
	if err != nil || canonical != raw {
		return m, errors.New("canonical sanitized manifest required")
	}
	return m, nil
}
