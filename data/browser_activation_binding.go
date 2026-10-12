package data

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

// BrowserActivationBindingAuthority is immutable, metadata-only provenance of an
// actual committed browser operation. It supplies no renderer or input authority.
type BrowserActivationBindingAuthority struct {
	Namespace             string `json:"namespace"`
	ID                    string `json:"id"`
	ClientID              string `json:"clientId"`
	Action                string `json:"action"`
	RunID                 string `json:"runId"`
	PlanID                string `json:"planId"`
	StepID                string `json:"stepId"`
	StepIndex             int    `json:"stepIndex"`
	DurableAttemptID      string `json:"durableAttemptId"`
	EffectID              string `json:"effectId"`
	BrowserAttemptID      string `json:"browserAttemptId"`
	ProfileChannel        string `json:"profileChannel"`
	BrowserInstance       string `json:"browserInstance"`
	Origin                string `json:"origin"`
	TabID                 int    `json:"tabId"`
	ChromePID             int    `json:"chromePid"`
	ChromeStartToken      string `json:"chromeStartToken"`
	NativeHostPID         int    `json:"nativeHostPid"`
	NativeHostStartToken  string `json:"nativeHostStartToken"`
	BrokerEpoch           string `json:"brokerEpoch"`
	ChannelEpoch          string `json:"channelEpoch"`
	ScopeHash             string `json:"scopeHash"`
	ChannelOperationEpoch int    `json:"channelOperationEpoch"`
	FingerprintVersion    int    `json:"fingerprintVersion"`
	FingerprintDigest     string `json:"fingerprintDigest"`
	PlanContentDigest     string `json:"planContentDigest"`
	StepDigest            string `json:"stepDigest"`
	BusinessKey           string `json:"businessKey"`
	BusinessKeyDigest     string `json:"businessKeyDigest"`
	CommittedRunRevision  int    `json:"committedRunRevision"`
	EndlySessionID        string `json:"endlySessionId"`
	EndlyOperationID      string `json:"endlyOperationId"`
	CreatedAt             string `json:"createdAt"`
}

type browserActivationBindingKey struct{}

func BrowserActivationBindingID(namespace, client, attempt string) string {
	return ChromeRetirementDigest([]string{"browser-activation-binding-v1", namespace, client, attempt})
}
func BrowserActivationFingerprint(a BrowserActivationBindingAuthority) string {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if encoder.Encode([]any{"mechanize-browser-activate-tab-v1", a.ProfileChannel, a.BrowserInstance, a.BrowserAttemptID, a.Origin, a.TabID, a.BrokerEpoch, a.ChannelEpoch, a.ScopeHash}) != nil {
		return ""
	}
	return ChromeAttemptRawDigest(strings.TrimSuffix(buffer.String(), "\n"))
}
func (a BrowserActivationBindingAuthority) Validate() error {
	for _, v := range []string{a.Namespace, a.ID, a.DurableAttemptID, a.EffectID, a.BrowserAttemptID, a.ScopeHash, a.FingerprintDigest, a.PlanContentDigest, a.StepDigest, a.BusinessKeyDigest} {
		if !retirementHash.MatchString(v) {
			return errors.New("exact browser activation binding digest required")
		}
	}
	for _, v := range []string{a.ClientID, a.RunID, a.PlanID, a.StepID, a.ProfileChannel, a.BrowserInstance, a.BrokerEpoch, a.ChannelEpoch, a.EndlySessionID, a.EndlyOperationID, a.ChromeStartToken, a.NativeHostStartToken} {
		if !retirementOpaque.MatchString(v) {
			return errors.New("exact bounded browser activation identity required")
		}
	}
	if a.Action != "browser.activateTab" || !model.ExactHTTPOrigin(a.Origin) || a.TabID < 1 || a.TabID > 2147483647 || a.ChromePID < 1 || a.NativeHostPID < 1 || a.ChannelOperationEpoch < 1 || a.StepIndex < 0 || a.StepIndex >= 2000 || a.FingerprintVersion != 1 || a.CommittedRunRevision < 1 || a.BusinessKey == "" || len(a.BusinessKey) > 65536 {
		return errors.New("exact activation operation binding required")
	}
	if a.ID != BrowserActivationBindingID(a.Namespace, a.ClientID, a.DurableAttemptID) || a.BrowserAttemptID != ChromeAttemptBrowserIDV2(a.Namespace, a.ClientID, a.DurableAttemptID) || a.EffectID != ChromeRetirementDigest([]string{"effect", a.DurableAttemptID}) || a.FingerprintDigest != BrowserActivationFingerprint(a) || a.BusinessKeyDigest != ChromeAttemptRawDigest(a.BusinessKey) {
		return errors.New("activation correlation differs from original command")
	}
	var key map[string]model.Value
	if json.Unmarshal([]byte(a.BusinessKey), &key) != nil || len(key) != 3 || !reflect.DeepEqual(key["origin"], model.Value{Kind: model.StringValue, String: a.Origin}) || !reflect.DeepEqual(key["tab"], model.Value{Kind: model.StringValue, String: a.ProfileChannel + "/" + a.BrowserInstance + "/" + strconv.Itoa(a.TabID)}) {
		return errors.New("canonical activation business key required")
	}
	request, ok := key["request"]
	if !ok || request.Kind != model.StringValue || len(request.String) < 1 || len(request.String) > 128 || request.Validate() != nil {
		return errors.New("bounded original activation request required")
	}
	if _, e := time.Parse(time.RFC3339Nano, a.CreatedAt); e != nil {
		return errors.New("activation binding timestamp required")
	}
	return nil
}
func validateBrowserActivationAuthority(ctx context.Context, a BrowserActivationBindingAuthority) error {
	p, e := auth.FromContext(ctx)
	if e != nil || p.Namespace != a.Namespace || p.ClientID != a.ClientID || !p.HasScope("desktop:control") {
		return auth.ErrUnauthorized
	}
	if _, e = RequireScope(ctx, a.Namespace); e != nil {
		return e
	}
	intent, e := RequireCommittedStepIntent(ctx, p)
	if e != nil {
		return e
	}
	if intent.RunID != a.RunID || intent.PlanID != a.PlanID || intent.StepID != a.StepID || intent.StepIndex != a.StepIndex || intent.AttemptID != a.DurableAttemptID || intent.EffectID != a.EffectID || intent.LeaseEpoch != a.ChannelOperationEpoch || intent.RunRevision != a.CommittedRunRevision || intent.SessionID != a.EndlySessionID || intent.OperationID != a.EndlyOperationID {
		return errors.New("activation binding differs from active committed intent")
	}
	if e = a.Validate(); e != nil {
		return e
	}
	at, _ := time.Parse(time.RFC3339Nano, a.CreatedAt)
	if at.After(time.Now().Add(time.Second)) || time.Since(at) > 30*time.Second {
		return errors.New("fresh activation binding required")
	}
	return ctx.Err()
}
func WithBrowserActivationBindingAuthority(ctx context.Context, a BrowserActivationBindingAuthority) (context.Context, error) {
	if e := validateBrowserActivationAuthority(ctx, a); e != nil {
		return nil, e
	}
	raw, e := json.Marshal(a)
	if e != nil {
		return nil, e
	}
	return context.WithValue(ctx, browserActivationBindingKey{}, string(raw)), nil
}
func RequireBrowserActivationBindingAuthority(ctx context.Context) (BrowserActivationBindingAuthority, error) {
	raw, ok := ctx.Value(browserActivationBindingKey{}).(string)
	var a BrowserActivationBindingAuthority
	if !ok || json.Unmarshal([]byte(raw), &a) != nil {
		return a, errors.New("trusted committed activation binding required")
	}
	return a, validateBrowserActivationAuthority(ctx, a)
}
