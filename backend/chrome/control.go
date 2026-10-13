package chrome

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
)

// ControlAuthority is server-owned evidence for one revocable renderer lease.
// A DOM binding survives lease retirement; the exact retired lease cannot dispatch.
type ControlAuthority struct {
	PrivateRecipientID                                                         string `json:"-"`
	AllWebsites                                                                bool   `json:"allWebsites,omitempty"`
	MutationFingerprintVersion                                                 int
	SelectOptionVersion                                                        int
	TrustScope                                                                 string `json:"trustScope"`
	ScopeQualified                                                             bool   `json:"scopeQualified"`
	ProfileQualified, ExtensionQualified, DocumentQualified, ExecutorQualified bool
	Owner, ClientID, ExtensionOrigin, BrokerEpoch, ChannelEpoch, ScopeHash     string
	Document                                                                   Document
	Evidence                                                                   nativepeer.ChromeProcessEvidence
	Lease                                                                      Lease
}

func (g *Gateway) controlSnapshot(ctx context.Context, p auth.Principal, surface model.Surface) (ControlAuthority, *channel, error) {
	return g.controlMetadataSnapshot(ctx, p, surface, true)
}

func (g *Gateway) controlMetadataSnapshot(ctx context.Context, p auth.Principal, surface model.Surface, verifyPrivacy bool) (ControlAuthority, *channel, error) {
	if err := authorize(ctx, p, true); err != nil {
		return ControlAuthority{}, nil, err
	}
	c, d, err := g.broker.selectDocument(p, surface)
	if err != nil {
		return ControlAuthority{}, nil, err
	}
	if err = g.broker.qualifyVisibilityUnknown(ctx, c); err != nil {
		return ControlAuthority{}, nil, err
	}
	if verifyPrivacy {
		if err = g.guardCredentialPrivacy(ctx, p, c, d, true); err != nil {
			return ControlAuthority{}, nil, err
		}
	} else {
		// Capability booleans confer no renderer authority. Published private
		// metadata may advertise transport only to its actual owning client.
		g.broker.mu.Lock()
		blocked := !scopeDisjointLocked(c, d.Identity) && (c.privateInspection != nil || c.privateCredential != nil || c.privateFlow != nil || c.privateAdvance != nil || c.privacyPending != nil || c.privacy != nil && (!c.privacy.active || !c.privacy.published || c.privacy.source.Owner != p.Namespace || c.privacy.source.ClientID != p.ClientID))
		g.broker.mu.Unlock()
		if blocked {
			return ControlAuthority{}, nil, errCredentialPrivacy
		}
	}
	g.broker.mu.Lock()
	for _, current := range c.documents {
		if current.DocumentID == d.DocumentID && current.TabID == d.TabID {
			d = current
			break
		}
	}
	g.broker.mu.Unlock()
	if err = g.broker.verifyChannelProcess(ctx, c); err != nil {
		return ControlAuthority{}, nil, err
	}
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	if c.fixtureOnly || c.processEvidence == nil || !c.processEvidence.KernelPeerQualified || !channelScopeQualified(c) || !c.executorQualified || !c.inventoryComplete || !c.grant.Principal.HasScope("desktop:control") || len(c.pending) > 0 || c.openOriginPending != nil || domUnknownBlockedLocked(c) || g.broker.closed || c.conn == nil {
		return ControlAuthority{}, nil, browserError("controlUnqualified", "Independent live production channel and idle executor required", "notDispatched")
	}
	e := *c.processEvidence
	e.Ancestors = append([]session.ProcessIdentity(nil), e.Ancestors...)
	return ControlAuthority{AllWebsites: c.grant.AllWebsites, MutationFingerprintVersion: c.mutationFingerprintVersion, SelectOptionVersion: c.selectOptionVersion, TrustScope: c.grant.TrustScope, ScopeQualified: channelScopeQualified(c), Owner: p.Namespace, ClientID: p.ClientID, ExtensionOrigin: c.grant.ExtensionOrigin, BrokerEpoch: g.broker.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, Document: d, Evidence: e, ProfileQualified: c.profileQualified, ExtensionQualified: c.grant.ExtensionOrigin != "", DocumentQualified: c.inventoryComplete, ExecutorQualified: c.executorQualified}, c, nil
}
func sameControl(a, b ControlAuthority) bool {
	return a.PrivateRecipientID == b.PrivateRecipientID && a.AllWebsites == b.AllWebsites && a.MutationFingerprintVersion == b.MutationFingerprintVersion && a.SelectOptionVersion == b.SelectOptionVersion && a.TrustScope == b.TrustScope && a.ScopeQualified == b.ScopeQualified && a.ProfileQualified == b.ProfileQualified && a.Owner == b.Owner && a.ClientID == b.ClientID && a.ExtensionOrigin == b.ExtensionOrigin && a.BrokerEpoch == b.BrokerEpoch && a.ChannelEpoch == b.ChannelEpoch && a.ScopeHash == b.ScopeHash && a.Document == b.Document && a.Evidence.NativeHost == b.Evidence.NativeHost && a.Evidence.ChromeParent == b.Evidence.ChromeParent && a.Lease == b.Lease
}
func (g *Gateway) controlCheck(ctx context.Context, p auth.Principal, a ControlAuthority, c *channel, retirement bool, navigationRetired ...bool) error {
	if err := authorize(ctx, p, true); err != nil {
		return err
	}
	actual, _ := auth.FromContext(ctx)
	if actual.ClientID != a.ClientID || p.Namespace != a.Owner || p.ClientID != a.ClientID {
		return auth.ErrUnauthorized
	}
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	if a.AllWebsites != c.grant.AllWebsites || !allowedOrigin(c.grant, a.Document.Origin) || a.MutationFingerprintVersion != c.mutationFingerprintVersion || a.SelectOptionVersion != c.selectOptionVersion || c.fixtureOnly || c.conn == nil || g.broker.closed || c.processEvidence == nil || !c.processEvidence.KernelPeerQualified || c.processEvidence.NativeHost != a.Evidence.NativeHost || c.processEvidence.ChromeParent != a.Evidence.ChromeParent || !channelScopeQualified(c) || !a.ScopeQualified || a.TrustScope != c.grant.TrustScope || a.ProfileQualified != c.profileQualified || !c.executorQualified || !c.inventoryComplete || g.broker.epoch != a.BrokerEpoch || c.epoch != a.ChannelEpoch || c.scopeHash != a.ScopeHash || c.grant.ExtensionOrigin != a.ExtensionOrigin {
		return browserError("staleAuthority", "Connected channel evidence changed", "notDispatched")
	}
	// A fingerprint-bound navigation receipt can prove the exact source lease
	// was retired before navigation. Channel/process checks above still apply.
	if retirement && len(navigationRetired) == 1 && navigationRetired[0] {
		return ctx.Err()
	}
	for _, d := range c.documents {
		if d.DocumentID == a.Document.DocumentID && d.TabID == a.Document.TabID && d.FrameID == 0 && d.Origin == a.Document.Origin && d.ProfileChannel == a.Document.ProfileChannel && d.BrowserInstance == a.Document.BrowserInstance && (retirement || d == a.Document || playwrightOwnEffectIdentityLocked(ctx, c, a.Document.Identity, d.Identity, &a.Lease)) {
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
	acquireNotInstalled bool
	// PreflightNoInput is local proof from a correlated non-ready inspection, never a wire authority claim.
	PreflightNoInput bool `json:"-"`
	CredentialStage  string
	// FailureStage is a host-only closed phase, never renderer text or values.
	FailureStage  string
	FailureReason string
	Authority     ControlAuthority
	Created       bool
	Confirmed     bool
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
	// Read authorization is deliberately ambient only within its read operation.
	// Never strip it and accidentally reinterpret that context as control authority.
	if ctx.Value(credentialPublicReadKey{}) != nil {
		return ControlAdmission{}, browserError("publicReadOnly", "Classified public-read context cannot admit renderer control", "notDispatched")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// Only admission owns this lane. Dispatch/retirement never wait on it;
	// controlMu is released before any peer verification, observation or RPC.
	select {
	case g.admissionLane <- struct{}{}:
		defer func() { <-g.admissionLane }()
	case <-ctx.Done():
		return ControlAdmission{}, ctx.Err()
	}
	// Retries are metadata-only and share the caller's original bounded budget.
	var original *ControlAuthority
	for attempt := 0; attempt < 3; attempt++ {
		admission, err := g.admitControlOnce(ctx, p, surface, original)
		if !admission.acquireNotInstalled {
			return admission, err
		}
		if original == nil {
			copy := admission.Authority
			original = &copy
		}
		if attempt == 2 || ctx.Err() != nil {
			return ControlAdmission{}, err
		}
	}
	return ControlAdmission{}, browserError("staleGeneration", "Metadata admission did not settle", "notDispatched")
}
func (g *Gateway) admitControlOnce(ctx context.Context, p auth.Principal, surface model.Surface, original *ControlAuthority) (ControlAdmission, error) {
	g.consumeTargetRetirement(p)
	g.controlMu.Lock()
	retiring, needsObservation := g.controlRetiring, g.control == nil
	g.controlMu.Unlock()
	if retiring {
		return ControlAdmission{}, browserError("authorityRetiring", "Prior authority retirement is not confirmed", "notDispatched")
	}
	if needsObservation {
		// Binding is a metadata operation. Serializing the source DOM would
		// unnecessarily block navigation away from credential/embedded forms.
		candidate, channel, err := g.controlSnapshot(ctx, p, surface)
		if err != nil {
			return ControlAdmission{}, err
		}
		if original != nil && !sameAdmissionTarget(*original, candidate) {
			return ControlAdmission{}, browserError("staleAuthority", "Original acquisition target changed", "notDispatched")
		}
		reply, err := g.broker.call(ctx, channel, Command{Action: "executor.validate", Identity: candidate.Document.Identity}, false, func() error { return g.controlCheck(ctx, p, candidate, channel, true) })
		if err != nil || !reply.Validated || reply.Error != nil || reply.Identity.DocumentID != candidate.Document.DocumentID || reply.Identity.TabID != candidate.Document.TabID || reply.Value != nil || len(reply.Nodes) != 0 || reply.NewDocument != nil || reply.ControlLease != nil || len(reply.Events) != 0 || reply.Name != "" {
			return ControlAdmission{}, errors.Join(err, browserError("authorityUnconfirmed", "Metadata-only renderer binding unconfirmed", "notDispatched"))
		}
	}
	a, c, err := g.controlSnapshot(ctx, p, surface)
	if err != nil {
		return ControlAdmission{}, err
	}
	if original != nil && !sameAdmissionTarget(*original, a) {
		return ControlAdmission{}, browserError("staleAuthority", "Original acquisition target changed", "notDispatched")
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
	g.broker.mu.Lock()
	originalConn := c.conn
	g.broker.mu.Unlock()
	reply, err := g.broker.call(ctx, c, Command{Action: action, Identity: a.Document.Identity, ControlLease: &a.Lease}, false, func() error { return g.VerifyControl(ctx, p, a) })
	if err != nil || !reply.Validated || reply.ControlLease == nil || *reply.ControlLease != a.Lease || reply.Identity != a.Document.Identity {
		if created && g.releaseRejectedAcquisition(ctx, p, a, c, originalConn, reply) {
			admission.Created = false
			admission.acquireNotInstalled = true
			return admission, reply.Error
		}
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
	if step.Action != "element.press" && step.Action != "element.fill" && step.Action != "element.select" && step.Action != "browser.navigate" && step.Action != "browser.activate" {
		return result, browserError("unsupportedAction", "Qualified renderer or browser action required", "notDispatched")
	}
	if step.Action == "element.select" && (commit == nil || a.SelectOptionVersion != 1 || a.MutationFingerprintVersion != 2 || a.Document.MutationFingerprintVersion != 2) {
		return result, browserError("unsupportedAction", "Select requires negotiated committed v2 document control", "notDispatched")
	}
	if err := step.Validate(); err != nil {
		return result, err
	}
	// The renderer/browser input budget must be the declared action timeout,
	// rather than the broker's generic 30-second RPC default. In particular,
	// the closed pointer adapter admits only short-lived input authority.
	ctx, cancel := context.WithTimeout(ctx, time.Duration(step.TimeoutMs)*time.Millisecond)
	defer cancel()
	surface := step.Target.Surface
	if surface.Kind != "web" || surface.Origin != a.Document.Origin || surface.BundleID != "" || surface.Title != "" && (a.Document.TitleTruncated || surface.Title != a.Document.Title) || surface.TabID != "" && surface.TabID != a.Document.QualifiedTabID() && surface.TabID != strconv.Itoa(a.Document.TabID) {
		return result, auth.ErrUnauthorized
	}

	if err := g.VerifyControl(ctx, p, a); err != nil {
		return result, err
	}
	var locator *Locator
	var err error
	browserAction := step.Action == "browser.navigate" || step.Action == "browser.activate"
	if step.Action == "browser.navigate" && !a.AllWebsites {
		return result, auth.ErrUnauthorized
	}
	if browserAction && commit == nil {
		return result, browserError("bindingRequired", "Browser actions require committed v2 dispatch", "notDispatched")
	}
	if !browserAction {
		locator, err = compileLocator(step.Target, bindings)
		if err != nil {
			return result, err
		}
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
	if step.Action == "element.fill" || step.Action == "element.select" {
		value, e := model.ResolveValue(step.Arguments["value"], bindings)
		if e != nil || value.Kind != model.StringValue {
			return result, browserError("invalidValue", "Resolved string mutation value required", "notDispatched")
		}
		cmd.Args = map[string]any{"value": value.String}
	}
	c := g.controlChannel(a)
	if step.Action == "browser.navigate" {
		args, e := step.ResolveArguments(bindings)
		if e != nil {
			return result, e
		}
		destination := args["url"].String
		origin, e := model.NavigationOrigin(destination)
		if e != nil || c == nil || !allowedOrigin(c.grant, origin) {
			return result, auth.ErrUnauthorized
		}
		cmd.Args = map[string]any{"url": destination}
	}
	var reply Reply
	if commit != nil {
		if locator != nil {
			ctx = context.WithValue(ctx, playwrightControlCheckKey{}, func(checkCtx context.Context) error { return g.VerifyControl(checkCtx, p, a) })
		}
		reply, err = g.broker.callBound(ctx, c, cmd, p, commit, func() error { return g.VerifyControl(ctx, p, a) })
	} else {
		reply, err = g.broker.call(ctx, c, cmd, true, func() error { return g.VerifyControl(ctx, p, a) })
	}
	if step.Action == "browser.navigate" && err == nil && reply.RetiredAuthorityQuiesced && reply.ControlLease != nil && *reply.ControlLease == a.Lease {
		g.controlMu.Lock()
		if g.control != nil && sameControl(*g.control, a) {
			copy := a
			g.navigationRetired = &copy
			g.controlRetiring = true
		}
		g.controlMu.Unlock()
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
	navigationRetired := g.navigationRetired != nil && sameControl(*g.navigationRetired, a)
	g.controlMu.Unlock()
	c := g.controlChannel(a)
	if c == nil {
		return false, auth.ErrUnauthorized
	}
	if err := g.broker.verifyChannelProcess(ctx, c); err != nil {
		return false, err
	}
	g.broker.mu.Lock()
	knownSourceRetirement := knownPressSourceRetirementLocked(c, a.Document.Identity, &a.Lease, g.broker.epoch)
	g.broker.mu.Unlock()
	check := func() error {
		g.broker.mu.Lock()
		known := knownSourceRetirement && knownPressSourceRetirementLocked(c, a.Document.Identity, &a.Lease, g.broker.epoch)
		g.broker.mu.Unlock()
		if knownSourceRetirement && !known {
			return browserError("retirementUnknown", "Original navigation receipt changed before retirement", "unknown")
		}
		if known {
			if err := g.broker.guardPrivacyCommand(ctx, c, Command{Action: "executor.retire", Identity: a.Document.Identity, ControlLease: &a.Lease}, false); err != nil {
				return err
			}
		}
		return g.controlCheck(ctx, p, a, c, true, navigationRetired || known)
	}
	if err := check(); err != nil {
		return false, err
	}
	g.broker.mu.Lock()
	idle := len(c.pending) == 0 && !domUnknownBlockedLocked(c)
	g.broker.mu.Unlock()
	if !idle {
		return false, browserError("executorUnknown", "In-flight or unknown actions prevent retirement proof", "unknown")
	}
	if !navigationRetired {
		reply, err := g.broker.call(ctx, c, Command{Action: "executor.retire", Identity: a.Document.Identity, ControlLease: &a.Lease}, false, check)
		// Normal renderer retirement reports its current document generation.
		// The broker already validates exact source identity with a monotonic
		// generation. Source-absence proof instead ACKs the original identity.
		if err != nil || !reply.RetiredAuthorityQuiesced || knownSourceRetirement && reply.Identity != a.Document.Identity || reply.ControlLease == nil || *reply.ControlLease != a.Lease {
			return false, errors.Join(err, browserError("retirementUnknown", "Exact renderer lease retirement unconfirmed", "unknown"))
		}
	}
	g.broker.mu.Lock()
	idle = len(c.pending) == 0 && !domUnknownBlockedLocked(c)
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
	g.navigationRetired = nil
	g.controlRetiring = false
	return true, nil
}
