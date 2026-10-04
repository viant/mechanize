package darwin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

// ValueMatchProof exports only an authenticated equality fact and actual helper
// metadata. It is not a value-read permission or a business completion claim.
type ValueMatchProof struct {
	Matches     bool
	ObservedAt  time.Time
	HelperEpoch string
	TargetRef   string
}

// ValueMatches is a private literal comparison for code-enrolled verification
// contracts. Callers must additionally authorize that original literal/target;
// this API cannot return the target's text or resolve Vault/input references.
func (g *Gateway) ValueMatches(ctx context.Context, p auth.Principal, target model.Selector, expected string) (ValueMatchProof, error) {
	if err := authorized(ctx, p, true); err != nil {
		return ValueMatchProof{}, err
	}
	actual, _ := auth.FromContext(ctx)
	if actual.ClientID != p.ClientID {
		return ValueMatchProof{}, auth.ErrUnauthorized
	}
	if err := target.Validate(); err != nil {
		return ValueMatchProof{}, err
	}
	if target.Surface.Kind != "native" || target.Surface.ProcessID <= 0 || target.Surface.ProcessStartToken == "" || target.Cardinality != "one" {
		return ValueMatchProof{}, nativeError("processIdentityRequired", "Exact native process and unique target required")
	}
	if err := model.ValidateLiteralText(expected); err != nil {
		return ValueMatchProof{}, err
	}
	protectedTarget := target
	protectedTarget.Surface = model.Surface{}
	body, _ := json.Marshal(protectedTarget)
	for _, marker := range []string{"password", "credential", "secret", "token", "securetextfield"} {
		if strings.Contains(strings.ToLower(string(body)), marker) {
			return ValueMatchProof{}, nativeError("valueMatchDenied", "Protected target comparison is unavailable")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	g.mu.Lock()
	defer g.mu.Unlock()
	windowScope, err := resolvedWindowScope(target.Scope.Window, nil)
	if err != nil {
		return ValueMatchProof{}, err
	}
	observation, err := g.observeWindowSnapshot(ctx, target.Surface, target.Scope.NativeRoot, false, windowScope)
	if err != nil {
		return ValueMatchProof{}, err
	}
	if !g.valueMatchesEnabled {
		return ValueMatchProof{}, nativeError("valueMatchUnsupported", "Helper does not advertise private literal comparison")
	}
	node, err := resolve(observation, target, nil)
	if err != nil {
		return ValueMatchProof{}, err
	}
	reply, err := g.call(ctx, "elements.valueMatches", map[string]any{"elementRef": node.Ref.ID, "generation": node.Ref.Generation, "expectedApp": target.Surface.BundleID, "expected": expected}, nil)
	if err != nil {
		return ValueMatchProof{}, err
	}
	var proof struct {
		Matches    *bool     `json:"matches"`
		PID        int       `json:"pid"`
		Birth      string    `json:"startToken"`
		Bundle     string    `json:"bundleID"`
		Ref        string    `json:"targetRef"`
		Generation uint64    `json:"generation"`
		RequestID  string    `json:"requestId"`
		ObservedAt time.Time `json:"observedAt"`
	}
	decoder := json.NewDecoder(bytes.NewReader(reply.Result))
	decoder.DisallowUnknownFields()
	if len(reply.Result) > 4096 || decoder.Decode(&proof) != nil || decoder.Decode(new(any)) != io.EOF || proof.Matches == nil || proof.PID != target.Surface.ProcessID || proof.Birth != target.Surface.ProcessStartToken || proof.Bundle != target.Surface.BundleID || proof.Ref != node.Ref.ID || proof.Generation != node.Ref.Generation || proof.RequestID == "" || proof.RequestID != reply.RequestID || reply.HelperEpoch == "" || reply.HelperEpoch != observation.Epoch || proof.ObservedAt.Before(observation.Started) || proof.ObservedAt.After(time.Now()) || time.Since(proof.ObservedAt) > 3*time.Second || ctx.Err() != nil {
		return ValueMatchProof{}, nativeError("valueMatchUnconfirmed", "Exact fresh literal comparison proof is unavailable")
	}
	return ValueMatchProof{Matches: *proof.Matches, ObservedAt: proof.ObservedAt, HelperEpoch: reply.HelperEpoch, TargetRef: proof.Ref}, nil
}
