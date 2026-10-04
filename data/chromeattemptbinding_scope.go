package data

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/viant/mechanize/auth"
)

// This sealed capability is minted by the host only inside the active synchronous
// dispatch after confirmed BeginAttempt. Its fields are not a transport grant.
type ChromeAttemptBindingAuthority struct {
	Namespace               string `json:"namespace"`
	ID                      string `json:"id"`
	ClientID                string `json:"clientId"`
	RunID                   string `json:"runId"`
	PlanID                  string `json:"planId"`
	StepID                  string `json:"stepId"`
	StepIndex               int    `json:"stepIndex"`
	DurableAttemptID        string `json:"durableAttemptId"`
	EffectID                string `json:"effectId"`
	BrowserAttemptID        string `json:"browserAttemptId"`
	ProfileChannel          string `json:"profileChannel"`
	BrowserInstance         string `json:"browserInstance"`
	BrokerEpoch             string `json:"brokerEpoch"`
	ChannelEpoch            string `json:"channelEpoch"`
	ScopeHash               string `json:"scopeHash"`
	TabID                   int    `json:"tabId"`
	FrameID                 int    `json:"frameId"`
	DocumentID              string `json:"documentId"`
	DocumentGeneration      int64  `json:"documentGeneration"`
	RendererLeaseID         string `json:"rendererLeaseId"`
	RendererLeaseGeneration int64  `json:"rendererLeaseGeneration"`
	FingerprintVersion      int    `json:"fingerprintVersion"`
	FingerprintDigest       string `json:"fingerprintDigest"`
	PlanContentDigest       string `json:"planContentDigest"`
	StepDigest              string `json:"stepDigest"`
	BusinessKeyDigest       string `json:"businessKeyDigest"`
	CommittedRunRevision    int    `json:"committedRunRevision"`
	EndlySessionID          string `json:"endlySessionId"`
	EndlyOperationID        string `json:"endlyOperationId"`
	CreatedAt               string `json:"createdAt"`
	GuardProof              string `json:"-"`
}
type chromeAttemptBindingAuthorityKey struct{}
type sealedChromeAttemptBinding struct {
	Authority  ChromeAttemptBindingAuthority
	GuardProof string
}

func ChromeAttemptBrowserIDV2(namespace, clientID, durableAttemptID string) string {
	sum := sha256.Sum256([]byte("mechanize.chrome.attempt.v2\x00" + namespace + "\x00" + clientID + "\x00" + durableAttemptID))
	return hex.EncodeToString(sum[:])
}
func ChromeAttemptRawDigest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
func ChromeAttemptBindingID(namespace, clientID, actualAttemptID string) string {
	return ChromeRetirementDigest([]string{"chrome-attempt-binding-v2", namespace, clientID, actualAttemptID})
}
func validateChromeAttemptBinding(ctx context.Context, a ChromeAttemptBindingAuthority) error {
	p, err := auth.FromContext(ctx)
	if err != nil || p.Namespace != a.Namespace || p.ClientID != a.ClientID || !p.HasScope("desktop:control") {
		return auth.ErrUnauthorized
	}
	if _, err := RequireScope(ctx, a.Namespace); err != nil {
		return err
	}
	intent, err := RequireCommittedStepIntent(ctx, p)
	if err != nil {
		return err
	}
	if intent.RunID != a.RunID || intent.PlanID != a.PlanID || intent.StepID != a.StepID || intent.StepIndex != a.StepIndex || intent.AttemptID != a.DurableAttemptID || intent.EffectID != a.EffectID || int64(intent.LeaseEpoch) != a.RendererLeaseGeneration || intent.RunRevision != a.CommittedRunRevision || intent.SessionID != a.EndlySessionID || intent.OperationID != a.EndlyOperationID {
		return errors.New("binding differs from active committed dispatch intent")
	}
	for _, value := range []string{a.ClientID, a.RunID, a.PlanID, a.StepID, a.ProfileChannel, a.BrowserInstance, a.BrokerEpoch, a.ChannelEpoch, a.DocumentID, a.RendererLeaseID, a.EndlySessionID, a.EndlyOperationID, a.GuardProof} {
		if !retirementOpaque.MatchString(value) {
			return errors.New("bounded exact active binding context required")
		}
	}
	for _, value := range []string{a.ID, a.DurableAttemptID, a.EffectID, a.BrowserAttemptID, a.ScopeHash, a.FingerprintDigest, a.PlanContentDigest, a.StepDigest, a.BusinessKeyDigest} {
		if !retirementHash.MatchString(value) {
			return errors.New("exact binding identity/digests required")
		}
	}
	if a.ID != ChromeAttemptBindingID(a.Namespace, a.ClientID, a.DurableAttemptID) || a.BrowserAttemptID != ChromeAttemptBrowserIDV2(a.Namespace, a.ClientID, a.DurableAttemptID) || a.EffectID != ChromeRetirementDigest([]string{"effect", a.DurableAttemptID}) || a.FingerprintVersion != 2 || a.StepIndex < 0 || a.StepIndex >= 2000 || a.TabID <= 0 || a.TabID > 2147483647 || a.FrameID != 0 || a.DocumentGeneration < 1 || a.DocumentGeneration > 9007199254740991 || a.RendererLeaseGeneration < 1 || a.RendererLeaseGeneration > 9007199254740991 || a.CommittedRunRevision < 1 {
		return errors.New("exact committed intent and qualified v2 root binding required")
	}
	at, err := time.Parse(time.RFC3339Nano, a.CreatedAt)
	if err != nil || at.After(time.Now().Add(time.Second)) || time.Since(at) > 30*time.Second {
		return errors.New("fresh binding admission timestamp required")
	}
	return ctx.Err()
}
func WithChromeAttemptBindingAuthority(ctx context.Context, a ChromeAttemptBindingAuthority) (context.Context, error) {
	if err := validateChromeAttemptBinding(ctx, a); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(sealedChromeAttemptBinding{a, a.GuardProof})
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, chromeAttemptBindingAuthorityKey{}, string(raw)), nil
}
func RequireChromeAttemptBindingAuthority(ctx context.Context) (ChromeAttemptBindingAuthority, error) {
	raw, ok := ctx.Value(chromeAttemptBindingAuthorityKey{}).(string)
	if !ok {
		return ChromeAttemptBindingAuthority{}, errors.New("trusted committed-intent binding authority required")
	}
	var sealed sealedChromeAttemptBinding
	if json.Unmarshal([]byte(raw), &sealed) != nil {
		return ChromeAttemptBindingAuthority{}, errors.New("invalid committed-intent authority")
	}
	sealed.Authority.GuardProof = sealed.GuardProof
	return sealed.Authority, validateChromeAttemptBinding(ctx, sealed.Authority)
}
func ValidateChromeAttemptBindingReader(ctx context.Context, namespace, clientID string) error {
	p, err := auth.FromContext(ctx)
	if err != nil || p.Namespace != namespace || p.ClientID != clientID || (!p.HasScope("desktop:observe") && !p.HasScope("desktop:control")) {
		return auth.ErrUnauthorized
	}
	_, err = RequireScope(ctx, namespace)
	return err
}
