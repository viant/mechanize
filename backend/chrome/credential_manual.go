package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"unicode/utf8"

	"github.com/viant/mechanize/session"
	"github.com/viant/mechanize/vault"
	"net"
	"os"
	"time"
)

var ErrManualCredentialPrivacy = errors.New("manual private document qualification unavailable")

// ManualCredentialPrivacyReason exposes only a closed refusal category, never
// error text or renderer data. It grants no authority and cannot accept callers'
// arbitrary error messages as a diagnostic.
func ManualCredentialPrivacyReason(err error) string {
	var failure *manualPrivacyRefusal
	if errors.As(err, &failure) && closedManualReason(failure.reason) {
		return failure.reason
	}
	return ""
}

type manualPrivacyRefusal struct{ reason string }

func (*manualPrivacyRefusal) Error() string {
	return "manual private document qualification unavailable"
}
func (*manualPrivacyRefusal) Unwrap() error { return ErrManualCredentialPrivacy }
func manualRefusal(reason string) error {
	if !closedManualReason(reason) {
		return ErrManualCredentialPrivacy
	}
	return &manualPrivacyRefusal{reason: reason}
}

// ManualCredentialSource is populated by the host's scoped immutable delivery
// records. No MCP arguments can supply a source or a credential value.
type ManualCredentialSource struct {
	Identity            Identity
	Origin, ChromeBirth string
}
type manualCredentialPending struct {
	requestID, proofID, kind string
	source                   Identity
	done                     chan []byte
}
type ManualCredentialTransition struct {
	gateway       *Gateway
	channel       *channel
	conn          net.Conn
	source        ManualCredentialSource
	authority     ControlAuthority
	binding       auth.ConsentBinding
	proofID       string
	admit         func(context.Context) error
	deadline      time.Time
	oldControl    *ControlAuthority
	documentMode  bool
	committed     bool
	refused       bool
	refusalReason string
}

func (ManualCredentialTransition) String() string { return "[private manual transition]" }
func (ManualCredentialTransition) MarshalJSON() ([]byte, error) {
	return nil, ErrManualCredentialPrivacy
}
func (b *Broker) acceptManualCredentialLocked(c *channel, raw []byte) bool {
	pending := c.manualPending
	if pending == nil {
		return false
	}
	defer clear(raw)
	var kind struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &kind) != nil {
		return true
	}
	if kind.Type == "documents" {
		return true
	}
	copy := append([]byte(nil), raw...)
	select {
	case pending.done <- copy:
	default:
		clear(copy)
	}
	return true
}
func (g *Gateway) BeginManualCredentialPrivacy(ctx context.Context, p auth.Principal, source ManualCredentialSource, admit func(context.Context) error) (*ManualCredentialTransition, error) {
	if g == nil || g.broker == nil || admit == nil || source.Identity.TabID <= 0 || source.Identity.FrameID != 0 || !fingerprintV2ID.MatchString(source.Identity.DocumentID) || source.Identity.ProfileChannel == "" || source.Identity.BrowserInstance == "" || source.Identity.Generation == 0 || source.Identity.Generation > 9007199254740991 || !OrdinaryWebsiteOrigin(source.Origin) || len(source.Origin) < 8 || source.Origin[:8] != "https://" || source.ChromeBirth == "" {
		return nil, ErrManualCredentialPrivacy
	}
	binding, ok := auth.ConsentBindingFromContext(ctx)
	actual, e := auth.FromContext(ctx)
	if !ok || e != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || binding.GrantID == "" || binding.SessionID == "" || !p.HasScope("desktop:control") || auth.NativeHuman(ctx) {
		return nil, ErrManualCredentialPrivacy
	}
	b := g.broker
	g.controlMu.Lock()
	oldControl := g.control
	retiring := g.controlRetiring
	g.controlMu.Unlock()
	b.mu.Lock()
	c := b.channels[channelKey(source.Identity.ProfileChannel, source.Identity.BrowserInstance)]
	if c == nil || c.grant.Principal.Namespace != p.Namespace || c.conn == nil || c.fixtureOnly || !channelScopeQualified(c) || c.lifecycleInhibited || len(c.pending) != 0 || len(c.unknown) != 0 || c.manualTransition != nil || retiring || !manualControlOwned(oldControl, p, source, c.privacy) {
		b.mu.Unlock()
		return nil, ErrManualCredentialPrivacy
	}
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	t := &ManualCredentialTransition{gateway: g, channel: c, conn: c.conn, source: source, oldControl: oldControl, binding: binding, proofID: newPrivateID(), admit: admit, deadline: deadline, documentMode: c.manualPrivacyDocumentVersion == 1}
	c.manualTransition = t
	b.mu.Unlock()
	if t.check(ctx, p) != nil {
		t.Abort()
		return nil, ErrManualCredentialPrivacy
	}
	raw, e := t.exchange(ctx, p, "credentialTabAbsent", nil)
	if e != nil {
		t.Abort()
		return nil, e
	}
	defer clear(raw)
	var reply struct {
		Type, RequestID, ProofID  string
		SourceIdentity            Identity
		Absent, InventoryComplete bool
		Reason                    string
	}
	if decodeManualReply(raw, &reply) != nil || reply.Type != "credentialTabAbsentResult" || reply.ProofID != t.proofID || reply.SourceIdentity != source.Identity {
		t.Abort()
		return nil, ErrManualCredentialPrivacy
	}
	if !reply.Absent || !reply.InventoryComplete || reply.Reason != "" {
		if closedManualReason(reply.Reason) && t.check(ctx, p) == nil {
			t.refused = true
		}
		t.Abort()
		if t.refused {
			return nil, manualRefusal(reply.Reason)
		}
		return nil, ErrManualCredentialPrivacy
	}
	return t, nil
}
func (t *ManualCredentialTransition) check(ctx context.Context, p auth.Principal) error {
	if t == nil || t.gateway == nil || ctx.Err() != nil || !time.Now().Before(t.deadline) || t.admit(ctx) != nil {
		return ErrManualCredentialPrivacy
	}
	actual, e := auth.FromContext(ctx)
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if e != nil || !ok || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || binding != t.binding {
		return ErrManualCredentialPrivacy
	}
	b, c := t.gateway.broker, t.channel
	if b.verifyChannelProcess(ctx, c) != nil {
		return ErrManualCredentialPrivacy
	}
	b.mu.Lock()
	valid := c.conn == t.conn && c.manualTransition == t && !b.closed && !c.lifecycleInhibited && len(c.pending) == 0 && len(c.unknown) == 0 && c.processEvidence != nil && channelScopeQualified(c) && allowedOrigin(c.grant, t.source.Origin)
	var evidence session.ProcessIdentity
	if c.processEvidence != nil {
		evidence = c.processEvidence.ChromeParent
	}
	b.mu.Unlock()
	if !valid {
		return ErrManualCredentialPrivacy
	}
	if evidence.StartToken != t.source.ChromeBirth && session.VerifyProcessBirthAbsent(ctx, uint32(os.Getuid()), t.source.ChromeBirth) != nil {
		return ErrManualCredentialPrivacy
	}
	return nil
}
func (t *ManualCredentialTransition) exchange(ctx context.Context, p auth.Principal, kind string, extra map[string]any) ([]byte, error) {
	if t.check(ctx, p) != nil {
		return nil, ErrManualCredentialPrivacy
	}
	b, c := t.gateway.broker, t.channel
	select {
	case b.lane <- struct{}{}:
		defer func() { <-b.lane }()
	case <-ctx.Done():
		return nil, ErrManualCredentialPrivacy
	}
	if target, ok := extra["identity"].(Identity); ok {
		var endBadge func()
		ctx, endBadge = b.beginControlBadge(ctx, c, target)
		defer endBadge()
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if t.check(ctx, p) != nil {
		return nil, ErrManualCredentialPrivacy
	}
	pending := &manualCredentialPending{requestID: newPrivateID(), proofID: t.proofID, kind: kind, source: t.source.Identity, done: make(chan []byte, 1)}
	b.mu.Lock()
	if c.manualPending != nil {
		b.mu.Unlock()
		return nil, ErrManualCredentialPrivacy
	}
	c.manualPending = pending
	command := map[string]any{"type": kind, "requestId": pending.requestID, "proofId": t.proofID, "sourceIdentity": t.source.Identity, "brokerEpoch": b.epoch, "channelEpoch": c.epoch, "scopeHash": c.scopeHash, "deadlineUnixMs": t.deadline.UnixMilli(), "origin": t.source.Origin}
	b.mu.Unlock()
	if t.documentMode {
		command["sourceDocumentAbsence"] = true
	}
	defer func() {
		b.mu.Lock()
		if c.manualPending == pending {
			c.manualPending = nil
		}
		b.mu.Unlock()
	}()
	secret, hasSecret := extra["privateSeed"].(credentialPayload)
	for k, v := range extra {
		if k != "privateSeed" {
			command[k] = v
		}
	}
	raw, e := json.Marshal(command)
	if e == nil && hasSecret {
		raw, e = encodeManualCredentialSeed(raw, secret)
	}
	if e != nil || len(raw) > 128*1024 {
		return nil, ErrManualCredentialPrivacy
	}
	defer clear(raw)
	if t.check(ctx, p) != nil {
		return nil, ErrManualCredentialPrivacy
	}
	_ = t.conn.SetWriteDeadline(t.deadline)
	e = writeCredentialDelivery(t.conn, raw)
	_ = t.conn.SetWriteDeadline(time.Time{})
	if e != nil {
		return nil, ErrManualCredentialPrivacy
	}
	timer := time.NewTimer(time.Until(t.deadline))
	defer timer.Stop()
	select {
	case raw := <-pending.done:
		var id struct {
			RequestID string `json:"requestId"`
			ProofID   string `json:"proofId"`
		}
		if len(raw) > 4096 || !uniqueCredentialJSON(raw) || json.Unmarshal(raw, &id) != nil || id.RequestID != pending.requestID || id.ProofID != t.proofID {
			clear(raw)
			return nil, ErrManualCredentialPrivacy
		}
		return raw, nil
	case <-ctx.Done():
		return nil, ErrManualCredentialPrivacy
	case <-timer.C:
		return nil, ErrManualCredentialPrivacy
	}
}
func decodeManualReply(raw []byte, out any) error {
	if len(raw) > 4096 || !uniqueCredentialJSON(raw) {
		return ErrManualCredentialPrivacy
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return ErrManualCredentialPrivacy
	}
	var kind string
	json.Unmarshal(fields["type"], &kind)
	required := []string{"type", "requestId", "proofId", "identity", "ready", "redactionReady", "privateInputRetired"}
	if kind == "credentialTabAbsentResult" {
		required = []string{"type", "requestId", "proofId", "sourceIdentity", "absent", "inventoryComplete"}
	} else if kind != "credentialManualPrivacyResult" {
		return ErrManualCredentialPrivacy
	}
	if len(fields) != len(required) && len(fields) != len(required)+1 {
		return ErrManualCredentialPrivacy
	}
	allowed := map[string]bool{"reason": true}
	for _, key := range required {
		allowed[key] = true
		if fields[key] == nil {
			return ErrManualCredentialPrivacy
		}
	}
	for key := range fields {
		if !allowed[key] {
			return ErrManualCredentialPrivacy
		}
	}
	return closedPlaywright(raw, out)
}
func (t *ManualCredentialTransition) Qualify(ctx context.Context, p auth.Principal, manager *vault.Manager, binding vault.Binding, ref vault.Reference, revision string) (CredentialPrivacyProof, error) {
	var identity Identity
	e := manager.ConsumeRevision(ctx, binding, ref, revision, func(secret vault.Credentials) error {
		return secret.WithBytes(func(user, password []byte) error {
			raw, e := t.exchange(ctx, p, "credentialManualPrivacy", map[string]any{"privateSeed": credentialPayload{user, password}})
			if e != nil {
				return e
			}
			defer clear(raw)
			var r struct {
				Type, RequestID, ProofID                   string
				Identity                                   *Identity
				Ready, RedactionReady, PrivateInputRetired bool
				Reason                                     string
			}
			if decodeManualReply(raw, &r) == nil && r.Type == "credentialManualPrivacyResult" && r.ProofID == t.proofID && !r.Ready && closedManualReason(r.Reason) && t.check(ctx, p) == nil {
				t.refused = true
				t.refusalReason = r.Reason
				return manualRefusal(r.Reason)
			}
			if decodeManualReply(raw, &r) != nil || r.Type != "credentialManualPrivacyResult" || r.ProofID != t.proofID || !r.Ready || !r.RedactionReady || !r.PrivateInputRetired || r.Identity == nil || r.Reason != "" {
				return ErrManualCredentialPrivacy
			}
			identity = *r.Identity
			return nil
		})
	})
	if e != nil {
		if t.refused && closedManualReason(t.refusalReason) {
			return CredentialPrivacyProof{}, manualRefusal(t.refusalReason)
		}
		if ManualCredentialPrivacyReason(e) != "" {
			return CredentialPrivacyProof{}, e
		}
		return CredentialPrivacyProof{}, ErrManualCredentialPrivacy
	}
	if identity.ProfileChannel != t.source.Identity.ProfileChannel || identity.BrowserInstance != t.source.Identity.BrowserInstance || identity.TabID <= 0 || identity.TabID == t.source.Identity.TabID && !t.documentMode || identity.DocumentID == t.source.Identity.DocumentID || identity.FrameID != 0 || !fingerprintV2ID.MatchString(identity.DocumentID) || identity.Generation == 0 || identity.Generation > 9007199254740991 {
		return CredentialPrivacyProof{}, ErrManualCredentialPrivacy
	}
	raw, e := t.exchange(ctx, p, "credentialManualPrivacyCommit", map[string]any{"identity": identity, "permitId": t.proofID})
	if e != nil {
		return CredentialPrivacyProof{}, e
	}
	defer clear(raw)
	var r struct {
		Type, RequestID, ProofID                   string
		Identity                                   *Identity
		Ready, RedactionReady, PrivateInputRetired bool
		Reason                                     string
	}
	if decodeManualReply(raw, &r) == nil && r.Type == "credentialManualPrivacyResult" && r.ProofID == t.proofID && !r.Ready && closedManualReason(r.Reason) && t.check(ctx, p) == nil {
		t.refused = true
		return CredentialPrivacyProof{}, manualRefusal(r.Reason)
	}
	if decodeManualReply(raw, &r) != nil || r.Type != "credentialManualPrivacyResult" || r.ProofID != t.proofID || r.Identity == nil || !sameManualDocument(identity, *r.Identity) || !r.Ready || !r.RedactionReady || !r.PrivateInputRetired || r.Reason != "" || t.check(ctx, p) != nil {
		return CredentialPrivacyProof{}, ErrManualCredentialPrivacy
	}
	identity = *r.Identity
	g, b, c := t.gateway, t.gateway.broker, t.channel
	g.controlMu.Lock()
	defer g.controlMu.Unlock()
	if g.control != t.oldControl || g.controlRetiring {
		return CredentialPrivacyProof{}, ErrManualCredentialPrivacy
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if c.manualTransition != t || c.conn != t.conn || c.processEvidence == nil {
		return CredentialPrivacyProof{}, ErrManualCredentialPrivacy
	}
	d := Document{Identity: identity, Origin: t.source.Origin, MutationFingerprintVersion: 2}
	d.TabHandle = d.QualifiedTabID()
	a := ControlAuthority{AllWebsites: c.grant.AllWebsites, Owner: p.Namespace, ClientID: p.ClientID, Document: d, ExtensionOrigin: c.grant.ExtensionOrigin, BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, TrustScope: c.grant.TrustScope, ScopeQualified: channelScopeQualified(c), ProfileQualified: c.profileQualified, MutationFingerprintVersion: 2, Evidence: *c.processEvidence}
	s := &credentialPrivacyState{gateway: g, channel: c, conn: t.conn, source: a, authority: a, binding: t.binding, permitID: t.proofID, identity: identity, admit: t.admit, active: true, published: true}
	g.control = nil
	g.controlRetiring = false
	g.navigationRetired = nil
	c.privacy = s
	c.privateFlow = nil
	c.privateInspection = nil
	c.privateAdvance = nil
	c.privateCredential = nil
	c.documents = []Document{d}
	c.executorQualified = true
	c.inventoryComplete = true
	c.manualTransition = nil
	t.committed = true
	return CredentialPrivacyProof{state: s}, nil
}
func (t *ManualCredentialTransition) Abort() {
	if t == nil || t.committed {
		return
	}
	b := t.gateway.broker
	b.mu.Lock()
	owned := t.channel.manualTransition == t && t.channel.conn == t.conn
	if t.channel.manualTransition == t {
		t.channel.manualTransition = nil
	}
	b.mu.Unlock()
	if owned && !t.refused {
		_ = t.conn.Close()
	}
}

func encodeManualCredentialSeed(header []byte, secret credentialPayload) ([]byte, error) {
	if len(secret.username) == 0 || len(secret.password) == 0 || len(secret.username)+len(secret.password) > 64*1024 || !utf8.Valid(secret.username) || !utf8.Valid(secret.password) || bytes.ContainsRune(secret.username, 0) || bytes.ContainsRune(secret.password, 0) {
		clear(header)
		return nil, ErrManualCredentialPrivacy
	}
	u, e := json.Marshal(string(secret.username))
	if e != nil {
		clear(header)
		return nil, ErrManualCredentialPrivacy
	}
	defer clear(u)
	pw, e := json.Marshal(string(secret.password))
	if e != nil {
		clear(header)
		return nil, ErrManualCredentialPrivacy
	}
	defer clear(pw)
	header = append(header[:len(header)-1], `,"username":`...)
	header = append(header, u...)
	header = append(header, `,"password":`...)
	header = append(header, pw...)
	header = append(header, '}')
	return header, nil
}

func closedManualReason(reason string) bool {
	switch reason {
	case "invalidRequest", "authorityChanged", "expired", "busy", "unknownEffects", "lifecycleInhibited", "sourceTabPresent", "inventoryUnavailable", "candidateUnavailable", "candidateAmbiguous", "candidateChanged", "documentNotReady", "redactionUnavailable":
		return true
	}
	return false
}

func sameManualDocument(before, after Identity) bool {
	return before.ProfileChannel == after.ProfileChannel && before.BrowserInstance == after.BrowserInstance && before.TabID == after.TabID && before.FrameID == after.FrameID && before.DocumentID == after.DocumentID && after.Generation >= before.Generation && after.Generation <= 9007199254740991
}

// Only the captured original-source or prior independently qualified manual
// document control can retire; it never supplies the successor's input lease.
func manualControlOwned(a *ControlAuthority, p auth.Principal, source ManualCredentialSource, previous *credentialPrivacyState) bool {
	if a == nil {
		return true
	}
	if a.Owner != p.Namespace || a.ClientID != p.ClientID || a.Document.ProfileChannel != source.Identity.ProfileChannel || a.Document.BrowserInstance != source.Identity.BrowserInstance {
		return false
	}
	if a.Document.TabID == source.Identity.TabID && a.Document.DocumentID == source.Identity.DocumentID {
		return true
	}
	return previous != nil && previous.active && previous.published && previous.authority.Owner == p.Namespace && previous.authority.ClientID == p.ClientID && sameControl(*a, previous.authority)
}
