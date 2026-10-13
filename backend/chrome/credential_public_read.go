package chrome

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
)

// This renderer classification is not a source-absence or credential-delivery
// proof. It grants no lease and is accepted only in the publicRead exchange.
type credentialPublicDocument struct {
	Version     int      `json:"version"`
	Identity    Identity `json:"identity"`
	RouteSHA256 string   `json:"routeSHA256"`
	Public      bool     `json:"public"`
}
type credentialPublicReadKey struct{}
type credentialPublicReadPermit struct {
	broker                                              *Broker
	channel                                             *channel
	conn                                                net.Conn
	owner, client, brokerEpoch, channelEpoch, scopeHash string
	consent                                             auth.ConsentBinding
	document                                            Document
	routeSHA256                                         string
	nativeHost, chromeParent                            session.ProcessIdentity
	expires                                             time.Time
}

func publicReadAction(action string) bool {
	switch action {
	case "observe", "read", "resolve", "executor.validate":
		return true
	}
	return false
}

// WithVerifiedCredentialPublicRead binds a short-lived read context to a fresh
// renderer classification on one authenticated tab. Retained private state,
// public inventory, input leases and durable receipts are never rewritten.
func (g *Gateway) WithVerifiedCredentialPublicRead(ctx context.Context, p auth.Principal, target model.Surface) (context.Context, error) {
	if g == nil || g.broker == nil || authorize(ctx, p, false) != nil || target.Kind != "web" || target.BundleID != "" || target.ProcessID != 0 || target.ProcessStartToken != "" || target.Title != "" || !OrdinaryWebsiteOrigin(target.Origin) {
		return nil, scopeFailure("scopeChanged")
	}
	actual, _ := auth.FromContext(ctx)
	consent, ok := auth.ConsentBindingFromContext(ctx)
	profile, instance, tab, valid := ownedTabParts(target.TabID)
	if !valid || !ok || consent.GrantID == "" || actual.ClientID != p.ClientID {
		return nil, scopeFailure("scopeChanged")
	}
	b := g.broker
	b.mu.Lock()
	c := b.channels[channelKey(profile, instance)]
	ready := c != nil && c.conn != nil && !c.fixtureOnly && channelScopeQualified(c) && (c.credentialPublicReadVersion == 2 || c.credentialPublicReadVersion == 1 && c.executorQualified) && c.grant.Principal.Namespace == p.Namespace && allowedOrigin(c.grant, target.Origin)
	b.mu.Unlock()
	if !ready {
		return nil, scopeFailure("scopeUnsupported")
	}
	// Version 2 routes only classified semantic reads and never queries or
	// adopts old mutation receipts. Legacy readers retain their ordinary gates.
	b.mu.Lock()
	semanticRead := c.credentialPublicReadVersion == 2
	b.mu.Unlock()
	if !semanticRead {
		if err := b.qualifyVisibilityUnknown(ctx, c); err != nil {
			return nil, err
		}
	}
	if err := b.checkChannelProcess(ctx, c, false); err != nil {
		return nil, scopeFailure("scopeChanged")
	}
	expires := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(expires) {
		expires = d
	}
	b.mu.Lock()
	if c.processEvidence == nil || !c.processEvidence.KernelPeerQualified || c.conn == nil {
		b.mu.Unlock()
		return nil, scopeFailure("scopeChanged")
	}
	permit := &credentialPublicReadPermit{broker: b, channel: c, conn: c.conn, owner: p.Namespace, client: p.ClientID, consent: consent, brokerEpoch: b.epoch, channelEpoch: c.epoch, scopeHash: c.scopeHash, nativeHost: c.processEvidence.NativeHost, chromeParent: c.processEvidence.ChromeParent, expires: expires}
	b.mu.Unlock()
	// Empty document/generation is deliberately routing metadata, not an
	// invented document identity. Only the returned renderer proof supplies it.
	source := CredentialProtectionScope{PreparationID: strings.Repeat("0", 64), Identity: Identity{ProfileChannel: profile, BrowserInstance: instance, TabID: tab}, Origin: target.Origin}
	r, err := g.credentialScopeExchange(ctx, p, source, "publicRead", tab, target.Origin, nil)
	if err != nil {
		return nil, err
	}
	proof := r.PublicDocument
	if proof == nil || proof.Version != 1 || !proof.Public || !fingerprintV2Hash.MatchString(proof.RouteSHA256) || proof.Identity.ProfileChannel != profile || proof.Identity.BrowserInstance != instance || proof.Identity.TabID != tab || proof.Identity.FrameID != 0 || !receiptIdentityValid(proof.Identity) || r.TargetIdentity != nil || r.LoginRouteSHA256 != "" {
		return nil, scopeFailure("scopeChanged")
	}
	permit.document = Document{Identity: proof.Identity, Origin: target.Origin}
	permit.routeSHA256 = proof.RouteSHA256
	verified := context.WithValue(ctx, credentialPublicReadKey{}, permit)
	b.mu.Lock()
	valid = permit.validLocked(verified, c, proof.Identity)
	b.mu.Unlock()
	if !valid {
		return nil, scopeFailure("scopeChanged")
	}
	return verified, nil
}

// Caller holds the broker mutex. Every command still performs its ordinary
// process verification, lifecycle/unknown checks and renderer-side classifier.
func (p *credentialPublicReadPermit) validLocked(ctx context.Context, c *channel, i Identity) bool {
	if p == nil || p.broker == nil || c == nil || p.channel != c || ctx.Err() != nil || !time.Now().Before(p.expires) || p.document.Identity != i {
		return false
	}
	actor, e := auth.FromContext(ctx)
	consent, ok := auth.ConsentBindingFromContext(ctx)
	return e == nil && ok && actor.Namespace == p.owner && actor.ClientID == p.client && consent == p.consent && authorize(ctx, actor, false) == nil &&
		!p.broker.closed && c.conn == p.conn && c.conn != nil && p.broker.epoch == p.brokerEpoch && c.epoch == p.channelEpoch && c.scopeHash == p.scopeHash && c.grant.Principal.Namespace == p.owner && allowedOrigin(c.grant, p.document.Origin) &&
		(c.credentialPublicReadVersion == 2 || c.credentialPublicReadVersion == 1 && c.executorQualified && !domUnknownBlockedLocked(c)) && channelScopeQualified(c) && !c.lifecycleInhibited && c.privateCredential == nil && c.privateAdvance == nil && c.privacyPending == nil && c.manualPending == nil &&
		c.processEvidence != nil && c.processEvidence.KernelPeerQualified && c.processEvidence.NativeHost == p.nativeHost && c.processEvidence.ChromeParent == p.chromeParent
}
func publicReadPermitLocked(ctx context.Context, c *channel, command Command, mutation bool) *credentialPublicReadPermit {
	if mutation || !publicReadAction(command.Action) || command.ControlLease != nil || command.AttemptID != "" {
		return nil
	}
	p, _ := ctx.Value(credentialPublicReadKey{}).(*credentialPublicReadPermit)
	if p.validLocked(ctx, c, command.Identity) {
		return p
	}
	return nil
}

// A correlated response still belongs to the read lane after its permit
// expires. Route it to ordinary reply validation, which discards its values;
// do not reinterpret it as unexpected private credential traffic.
func ownedPublicReadPendingLocked(c *channel, p *pending) bool {
	if p == nil || p.publicReadContext == nil || p.mutation || !publicReadAction(p.command.Action) || p.command.ControlLease != nil || p.command.AttemptID != "" {
		return false
	}
	permit, _ := p.publicReadContext.Value(credentialPublicReadKey{}).(*credentialPublicReadPermit)
	return permit != nil && permit.channel == c && permit.conn == c.conn && permit.document.Identity == p.command.Identity
}
func (b *Broker) selectReadDocument(ctx context.Context, p auth.Principal, s model.Surface) (*channel, Document, error) {
	permit, _ := ctx.Value(credentialPublicReadKey{}).(*credentialPublicReadPermit)
	if permit == nil {
		return b.selectDocument(p, s)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if permit.broker != b || p.Namespace != permit.owner || p.ClientID != permit.client || s.Kind != "web" || s.Origin != permit.document.Origin || s.TabID != permit.document.QualifiedTabID() || s.BundleID != "" || s.ProcessID != 0 || s.ProcessStartToken != "" || s.Title != "" || !permit.validLocked(ctx, permit.channel, permit.document.Identity) {
		return nil, Document{}, scopeFailure("scopeChanged")
	}
	return permit.channel, permit.document, nil
}

// NeedsVerifiedPublicRead selects the existing v2 read protocol when an exact
// selected tab cannot use the ordinary executor. This hint grants no authority;
// WithVerifiedCredentialPublicRead still proves the actual current renderer.
func (g *Gateway) NeedsVerifiedPublicRead(ctx context.Context, p auth.Principal, target model.Surface) bool {
	if g == nil || g.broker == nil || authorize(ctx, p, false) != nil || target.Kind != "web" || !OrdinaryWebsiteOrigin(target.Origin) {
		return false
	}
	actual, e := auth.FromContext(ctx)
	profile, instance, tab, valid := ownedTabParts(target.TabID)
	if e != nil || actual.ClientID != p.ClientID || !valid {
		return false
	}
	b := g.broker
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.channels[channelKey(profile, instance)]
	if c == nil || c.grant.Principal.Namespace != p.Namespace || c.credentialPublicReadVersion != 2 || !allowedOrigin(c.grant, target.Origin) {
		return false
	}
	if !c.executorQualified || !c.inventoryComplete || domUnknownBlockedLocked(c) {
		return true
	}
	for _, document := range c.documents {
		if document.TabID == tab && document.Origin == target.Origin {
			return false
		}
	}
	return true
}
