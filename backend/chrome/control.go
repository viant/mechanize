package chrome

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
)

// ControlAuthority is server-owned evidence for one revocable renderer lease.
// A DOM binding survives lease retirement; the exact retired lease cannot dispatch.
type ControlAuthority struct {
	MutationFingerprintVersion                                                 int
	TrustScope                                                                 string `json:"trustScope"`
	ScopeQualified                                                             bool   `json:"scopeQualified"`
	ProfileQualified, ExtensionQualified, DocumentQualified, ExecutorQualified bool
	Owner, ClientID, ExtensionOrigin, BrokerEpoch, ChannelEpoch, ScopeHash     string
	Document                                                                   Document
	Evidence                                                                   nativepeer.ChromeProcessEvidence
	Lease                                                                      Lease
}

func (g *Gateway) controlSnapshot(ctx context.Context, p auth.Principal, surface model.Surface) (ControlAuthority, *channel, error) {
	if err := authorize(ctx, p, true); err != nil {
		return ControlAuthority{}, nil, err
	}
	c, d, err := g.broker.selectDocument(p, surface)
	if err != nil {
		return ControlAuthority{}, nil, err
	}
	if err = g.broker.verifyChannelProcess(ctx, c); err != nil {
		return ControlAuthority{}, nil, err
	}
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	if c.fixtureOnly || c.processEvidence == nil || !c.processEvidence.KernelPeerQualified || !channelScopeQualified(c) || !c.executorQualified || !c.inventoryComplete || !c.grant.Principal.HasScope("desktop:control") || len(c.pending) > 0 || len(c.unknown) > 0 || g.broker.closed || c.conn == nil {
		return ControlAuthority{}, nil, browserError("controlUnqualified", "Independent live production channel and idle executor required", "notDispatched")
	}
	e := *c.processEvidence
	e.Ancestors = append([]session.ProcessIdentity(nil), e.Ancestors...)
	return ControlAuthority{MutationFingerprintVersion: c.mutationFingerprintVersion, TrustScope: c.grant.TrustScope, ScopeQualified: channelScopeQualified(c), Owner: p.Namespace, ClientID: p.ClientID, ExtensionOrigin: c.grant.ExtensionOrigin, BrokerEpoch: g.broker.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, Document: d, Evidence: e, ProfileQualified: c.profileQualified, ExtensionQualified: c.grant.ExtensionOrigin != "", DocumentQualified: c.inventoryComplete, ExecutorQualified: c.executorQualified}, c, nil
}
func sameControl(a, b ControlAuthority) bool {
	return a.MutationFingerprintVersion == b.MutationFingerprintVersion && a.TrustScope == b.TrustScope && a.ScopeQualified == b.ScopeQualified && a.ProfileQualified == b.ProfileQualified && a.Owner == b.Owner && a.ClientID == b.ClientID && a.ExtensionOrigin == b.ExtensionOrigin && a.BrokerEpoch == b.BrokerEpoch && a.ChannelEpoch == b.ChannelEpoch && a.ScopeHash == b.ScopeHash && a.Document == b.Document && a.Evidence.NativeHost == b.Evidence.NativeHost && a.Evidence.ChromeParent == b.Evidence.ChromeParent && a.Lease == b.Lease
}
func (g *Gateway) controlCheck(ctx context.Context, p auth.Principal, a ControlAuthority, c *channel, retirement bool) error {
	if err := authorize(ctx, p, true); err != nil {
		return err
	}
	actual, _ := auth.FromContext(ctx)
	if actual.ClientID != a.ClientID || p.Namespace != a.Owner || p.ClientID != a.ClientID {
		return auth.ErrUnauthorized
	}
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	if a.MutationFingerprintVersion != c.mutationFingerprintVersion || c.fixtureOnly || c.conn == nil || g.broker.closed || c.processEvidence == nil || !c.processEvidence.KernelPeerQualified || c.processEvidence.NativeHost != a.Evidence.NativeHost || c.processEvidence.ChromeParent != a.Evidence.ChromeParent || !channelScopeQualified(c) || !a.ScopeQualified || a.TrustScope != c.grant.TrustScope || a.ProfileQualified != c.profileQualified || !c.executorQualified || !c.inventoryComplete || g.broker.epoch != a.BrokerEpoch || c.epoch != a.ChannelEpoch || c.scopeHash != a.ScopeHash || c.grant.ExtensionOrigin != a.ExtensionOrigin {
		return browserError("staleAuthority", "Connected channel evidence changed", "notDispatched")
	}
	for _, d := range c.documents {
		if d.DocumentID == a.Document.DocumentID && d.TabID == a.Document.TabID && d.FrameID == 0 && d.Origin == a.Document.Origin && d.ProfileChannel == a.Document.ProfileChannel && d.BrowserInstance == a.Document.BrowserInstance && (retirement || d == a.Document) {
			return ctx.Err()
		}
	}
	return browserError("staleAuthority", "Pinned document changed", "notDispatched")
}
func (g *Gateway) controlChannel(a ControlAuthority) *channel {
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	return g.broker.channels[channelKey(a.Document.ProfileChannel, a.Document.BrowserInstance)]
}

// AdmitControl verifies the actual signed peer and endpoint, then admits a new
// exclusive lease. A still-live lease is returned only to its same verified actor.
// ControlAdmission reports ownership from the actual exclusive admission lane.
// Created means this call installed the retained lease; it does not imply that
// acquire was acknowledged or that an uncertain lease was safely cleaned up.
type ControlAdmission struct {
	Authority ControlAuthority
	Created   bool
	Confirmed bool
}

// AdmitControl preserves the existing public success/error contract.
func (g *Gateway) AdmitControl(ctx context.Context, p auth.Principal, surface model.Surface) (ControlAuthority, error) {
	admission, err := g.AdmitControlWithStatus(ctx, p, surface)
	if err != nil {
		return ControlAuthority{}, err
	}
	return admission.Authority, nil
}

func (g *Gateway) AdmitControlWithStatus(ctx context.Context, p auth.Principal, surface model.Surface) (ControlAdmission, error) {
	// Only admission owns this lane. Dispatch/retirement never wait on it;
	// controlMu is released before any peer verification, observation or RPC.
	select {
	case g.admissionLane <- struct{}{}:
		defer func() { <-g.admissionLane }()
	case <-ctx.Done():
		return ControlAdmission{}, ctx.Err()
	}
	g.controlMu.Lock()
	retiring, needsObservation := g.controlRetiring, g.control == nil
	g.controlMu.Unlock()
	if retiring {
		return ControlAdmission{}, browserError("authorityRetiring", "Prior authority retirement is not confirmed", "notDispatched")
	}
	if needsObservation {
		if _, err := g.Observe(ctx, p, surface); err != nil {
			return ControlAdmission{}, err
		}
	}
	a, c, err := g.controlSnapshot(ctx, p, surface)
	if err != nil {
		return ControlAdmission{}, err
	}
	g.controlMu.Lock()
	if g.controlRetiring {
		g.controlMu.Unlock()
		return ControlAdmission{}, browserError("authorityRetiring", "Prior authority retirement is not confirmed", "notDispatched")
	}
	created := false
	if g.control != nil {
		a.Lease = g.control.Lease
		if !sameControl(a, *g.control) {
			g.controlMu.Unlock()
			return ControlAdmission{}, browserError("authorityBusy", "A different pinned authority remains active", "notDispatched")
		}
	} else {
		created = true
		g.controlGeneration++
		a.Lease = Lease{ID: newID(), Generation: g.controlGeneration}
		copy := a
		g.control = &copy // Retain ambiguity if acquire loses its reply.
	}
	g.controlMu.Unlock()

	admission := ControlAdmission{Authority: a, Created: created}
	action := "executor.acquire"
	reply, err := g.broker.call(ctx, c, Command{Action: action, Identity: a.Document.Identity, ControlLease: &a.Lease}, false, func() error { return g.VerifyControl(ctx, p, a) })
	if err != nil || !reply.Validated || reply.ControlLease == nil || *reply.ControlLease != a.Lease || reply.Identity != a.Document.Identity {
		return admission, errors.Join(err, browserError("authorityUnconfirmed", "Renderer lease admission is unconfirmed", "notDispatched"))
	}
	if err = g.VerifyControl(ctx, p, a); err != nil {
		return admission, err
	}
	admission.Confirmed = true
	return admission, nil
}
func (g *Gateway) VerifyControl(ctx context.Context, p auth.Principal, a ControlAuthority) error {
	g.controlMu.Lock()
	valid := g.control != nil && !g.controlRetiring && sameControl(*g.control, a)
	g.controlMu.Unlock()
	if !valid {
		return browserError("staleAuthority", "Renderer lease retired or substituted", "notDispatched")
	}
	c := g.controlChannel(a)
	if c == nil {
		return auth.ErrUnauthorized
	}
	if err := g.broker.verifyChannelProcess(ctx, c); err != nil {
		return err
	}
	return g.controlCheck(ctx, p, a, c, false)
}

// ExecuteControl never observes/reselects a replacement document. Its exact
// lease is checked again under the transport write lock and by the renderer.
func (g *Gateway) ExecuteControl(ctx context.Context, p auth.Principal, step model.Step, bindings map[string]model.Value, a ControlAuthority) (integration.StepResult, error) {
	return g.executeControl(ctx, p, step, bindings, a, "", nil)
}

// ExecuteControlBound requires explicit v2 worker/document negotiation and a
// committed readback of the exact logical mutation before transport.
func (g *Gateway) ExecuteControlBound(ctx context.Context, p auth.Principal, step model.Step, bindings map[string]model.Value, a ControlAuthority, browserAttemptID string, commit CommitMutationBinding) (integration.StepResult, error) {
	if !fingerprintV2Hash.MatchString(browserAttemptID) || commit == nil || a.MutationFingerprintVersion != 2 || a.Document.MutationFingerprintVersion != 2 {
		return integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, browserError("bindingRequired", "Negotiated v2 document and committed binding callback required", "notDispatched")
	}
	return g.executeControl(ctx, p, step, bindings, a, browserAttemptID, commit)
}
func (g *Gateway) executeControl(ctx context.Context, p auth.Principal, step model.Step, bindings map[string]model.Value, a ControlAuthority, browserAttemptID string, commit CommitMutationBinding) (integration.StepResult, error) {
	result := integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
	if step.Action != "element.press" && step.Action != "element.fill" {
		return result, browserError("unsupportedAction", "Qualified renderer press/fill required", "notDispatched")
	}
	if err := step.Validate(); err != nil {
		return result, err
	}
	surface := step.Target.Surface
	if surface.Kind != "web" || surface.Origin != a.Document.Origin || surface.BundleID != "" || surface.Title != "" && (a.Document.TitleTruncated || surface.Title != a.Document.Title) || surface.TabID != "" && surface.TabID != a.Document.QualifiedTabID() && surface.TabID != strconv.Itoa(a.Document.TabID) {
		return result, auth.ErrUnauthorized
	}

	if err := g.VerifyControl(ctx, p, a); err != nil {
		return result, err
	}
	locator, err := compileLocator(step.Target, bindings)
	if err != nil {
		return result, err
	}
	meta, ok := integration.ExecutionFromContext(ctx)
	if !ok || meta.RunID == "" || meta.PlanID == "" {
		return result, browserError("attemptIdentityRequired", "Durable Endly attempt required", "notDispatched")
	}
	hash := sha256.Sum256([]byte(meta.RunID + "\x00" + meta.PlanID + "\x00" + step.ID))
	cmd := Command{Action: step.Action, Identity: a.Document.Identity, Locator: locator, AttemptID: hex.EncodeToString(hash[:]), ControlLease: &a.Lease}
	if commit != nil {
		cmd.AttemptID = browserAttemptID
		cmd.FingerprintVersion = 2
	}
	if step.Action == "element.fill" {
		value, e := model.ResolveValue(step.Arguments["value"], bindings)
		if e != nil || value.Kind != model.StringValue {
			return result, browserError("invalidValue", "Resolved string fill required", "notDispatched")
		}
		cmd.Args = map[string]any{"value": value.String}
	}
	c := g.controlChannel(a)
	var reply Reply
	if commit != nil {
		reply, err = g.broker.callBound(ctx, c, cmd, p, commit, func() error { return g.VerifyControl(ctx, p, a) })
	} else {
		reply, err = g.broker.call(ctx, c, cmd, true, func() error { return g.VerifyControl(ctx, p, a) })
	}
	result.DispatchState = reply.DispatchState
	if result.DispatchState == "" {
		result.DispatchState = "notDispatched"
		var detail *model.MechanizeError
		if errors.As(err, &detail) {
			result.DispatchState = detail.DispatchState
		}
	}
	return result, err
}

// RetireControl revokes dispatch at the broker before asking the exact endpoint
// to revoke that lease. This is not executor.quiesce (whole-document shutdown).
func (g *Gateway) RetireControl(ctx context.Context, p auth.Principal, a ControlAuthority) (bool, error) {
	g.controlMu.Lock()
	if g.control == nil || !sameControl(*g.control, a) {
		g.controlMu.Unlock()
		return false, browserError("staleAuthority", "Exact live authority required for retirement", "notDispatched")
	}
	g.controlRetiring = true
	g.controlMu.Unlock()
	c := g.controlChannel(a)
	if c == nil {
		return false, auth.ErrUnauthorized
	}
	if err := g.broker.verifyChannelProcess(ctx, c); err != nil {
		return false, err
	}
	if err := g.controlCheck(ctx, p, a, c, true); err != nil {
		return false, err
	}
	g.broker.mu.Lock()
	idle := len(c.pending) == 0 && len(c.unknown) == 0
	g.broker.mu.Unlock()
	if !idle {
		return false, browserError("executorUnknown", "In-flight or unknown actions prevent retirement proof", "unknown")
	}
	reply, err := g.broker.call(ctx, c, Command{Action: "executor.retire", Identity: a.Document.Identity, ControlLease: &a.Lease}, false, func() error { return g.controlCheck(ctx, p, a, c, true) })
	if err != nil || !reply.RetiredAuthorityQuiesced || reply.ControlLease == nil || *reply.ControlLease != a.Lease {
		return false, errors.Join(err, browserError("retirementUnknown", "Exact renderer lease retirement unconfirmed", "unknown"))
	}
	g.broker.mu.Lock()
	idle = len(c.pending) == 0 && len(c.unknown) == 0
	g.broker.mu.Unlock()
	if !idle {
		return false, browserError("executorUnknown", "Pending or unknown actions remain after retirement", "unknown")
	}
	g.controlMu.Lock()
	defer g.controlMu.Unlock()
	if g.control == nil || !sameControl(*g.control, a) {
		return false, browserError("staleAuthority", "Authority changed during retirement", "unknown")
	}
	g.control = nil
	g.controlRetiring = false
	return true, nil
}
