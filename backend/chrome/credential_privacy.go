package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

var errCredentialPrivacy = errors.New("fresh private DOM qualification unavailable")

// Qualification exposes only closed host-defined phases, never renderer text,
// credential values, binding identifiers or underlying private errors.
type credentialPrivacyFailure string

func (f credentialPrivacyFailure) Error() string {
	return "fresh private DOM qualification unavailable"
}
func (f credentialPrivacyFailure) Is(target error) bool { return target == errCredentialPrivacy }
func CredentialPrivacyFailureCode(err error) string {
	var f credentialPrivacyFailure
	if !errors.As(err, &f) {
		return "postSubmitPrivacyUnavailable"
	}
	switch string(f) {
	case "notReady":
		return "postSubmitPrivacyNotReady"
	case "admission", "fence", "reply", "commit", "probe", "promotion":
		return "postSubmitPrivacy" + map[string]string{"admission": "Admission", "fence": "Fence", "reply": "Reply", "commit": "Commit", "probe": "Probe", "promotion": "Promotion"}[string(f)] + "Unavailable"
	}
	return "postSubmitPrivacyUnavailable"
}

var ErrCredentialPrivacyDocumentChanged = errors.New("private DOM document changed; fresh qualification required")

// CredentialPrivacyProof is an opaque live DOM-only capability. It cannot be
// deserialized, minted from a context flag, or used for native/image/recording.
type CredentialPrivacyProof struct{ state *credentialPrivacyState }

func (CredentialPrivacyProof) String() string               { return "[private DOM proof]" }
func (CredentialPrivacyProof) GoString() string             { return "[private DOM proof]" }
func (CredentialPrivacyProof) MarshalJSON() ([]byte, error) { return nil, errCredentialPrivacy }

// Authority returns a routing/provenance snapshot with no dispatch lease.
// The first ordinary operation must acquire its own fresh renderer lease under
// the retained DOM proof; publishing privacy alone grants no input authority.
func (p CredentialPrivacyProof) Authority() (ControlAuthority, bool) {
	if p.state == nil || p.state.gateway == nil {
		return ControlAuthority{}, false
	}
	s := p.state
	b := s.gateway.broker
	b.mu.Lock()
	defer b.mu.Unlock()
	if !s.published || !s.active || s.channel.privacy != s || s.channel.conn != s.conn || b.closed {
		return ControlAuthority{}, false
	}
	return s.authority, true
}

type credentialPrivacyState struct {
	gateway            *Gateway
	channel            *channel
	conn               net.Conn
	source, authority  ControlAuthority
	binding            auth.ConsentBinding
	submitID, permitID string
	identity           Identity
	admit              func(context.Context) error
	active, published  bool
	changed            bool
	allowSameDocument  bool
}
type credentialPrivacyPending struct {
	requestID, attemptID, permitID string
	expected                       Identity
	newDocument                    bool
	allowSameDocument              bool
	allowNavigation, changed       bool
	done                           chan Identity
	replied, failed, notReady      bool
}

func (b *Broker) acceptCredentialPrivacyLocked(c *channel, raw []byte) bool {
	var correlation struct {
		Type      string
		RequestID string `json:"requestId"`
	}
	if json.Unmarshal(raw, &correlation) != nil || correlation.Type != "credentialPrivacyResult" {
		return false
	}
	defer clear(raw)
	p := c.privacyPending
	// Old privacy replies never belong to a successor qualification or a DOM
	// read. Wipe them without poisoning the current authenticated channel.
	if p == nil || correlation.RequestID != p.requestID {
		return true
	}
	var r struct {
		Type      string   `json:"type"`
		RequestID string   `json:"requestId"`
		AttemptID string   `json:"attemptId"`
		Identity  Identity `json:"identity"`
		Ready     *bool    `json:"ready"`
		Retired   *bool    `json:"retiredAuthorityQuiesced"`
		Redaction *bool    `json:"redactionReady"`
		PermitID  string   `json:"permitId"`
		Changed   *bool    `json:"documentChanged"`
	}
	var fields, idFields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	_ = json.Unmarshal(fields["identity"], &idFields)
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	valid := len(raw) <= 4096 && uniqueCredentialJSON(raw) && (len(fields) == 8 || p.allowNavigation && len(fields) == 9) && len(idFields) == 6 && d.Decode(&r) == nil && d.Decode(new(any)) == io.EOF
	for _, key := range []string{"type", "requestId", "attemptId", "identity", "ready", "retiredAuthorityQuiesced", "redactionReady", "permitId"} {
		valid = valid && fields[key] != nil
	}
	for _, key := range []string{"profileChannel", "browserInstance", "tabId", "frameId", "documentId", "documentGeneration"} {
		v, ok := idFields[key]
		valid = valid && ok && !bytes.Equal(v, []byte("null"))
	}
	valid = valid && r.Type == "credentialPrivacyResult" && r.RequestID == p.requestID && r.AttemptID == p.attemptID && r.PermitID == p.permitID && r.Ready != nil && r.Retired != nil && r.Redaction != nil && r.Identity.ProfileChannel == p.expected.ProfileChannel && r.Identity.BrowserInstance == p.expected.BrowserInstance && r.Identity.TabID == p.expected.TabID && r.Identity.FrameID == 0 && fingerprintV2ID.MatchString(r.Identity.DocumentID) && r.Identity.Generation > 0 && r.Identity.Generation <= 9007199254740991
	changed := p.allowNavigation && r.Changed != nil && *r.Changed && r.Ready != nil && !*r.Ready && r.Identity.DocumentID != p.expected.DocumentID && len(fields) == 9
	if changed {
		valid = valid && *r.Retired && *r.Redaction
		p.changed = true
	} else {
		valid = valid && r.Changed == nil && len(fields) == 8 && r.Ready != nil
		if p.newDocument {
			valid = valid && (r.Identity.DocumentID != p.expected.DocumentID || (!*r.Ready || p.allowSameDocument) && r.Identity.Generation >= p.expected.Generation)
		} else {
			valid = valid && r.Identity.DocumentID == p.expected.DocumentID && r.Identity.Generation >= p.expected.Generation
		}
	}
	if valid && !changed {
		if *r.Ready {
			valid = *r.Retired && *r.Redaction
		} else {
			p.notReady = true
		}
	}
	if p.replied || !valid {
		p.failed = true
		r.Identity = Identity{}
		if c.privacy != nil {
			c.privacy.active = false
		}
		if c.conn != nil {
			_ = c.conn.Close()
		}
	}
	p.replied = true
	select {
	case p.done <- r.Identity:
	default:
	}
	return true
}
func privacyActor(ctx context.Context, p auth.Principal, s *credentialPrivacyState, mutation bool) bool {
	if s == nil || s.admit == nil || authorize(ctx, p, mutation) != nil || ctx.Err() != nil {
		return false
	}
	actual, e := auth.FromContext(ctx)
	binding, ok := auth.ConsentBindingFromContext(ctx)
	return e == nil && ok && actual.Namespace == s.source.Owner && actual.ClientID == s.source.ClientID && p.Namespace == s.source.Owner && p.ClientID == s.source.ClientID && binding == s.binding && s.admit(ctx) == nil
}
func (g *Gateway) privacyChannel(ctx context.Context, p auth.Principal, s *credentialPrivacyState) error {
	if !privacyActor(ctx, p, s, false) {
		return credentialPrivacyFailure("admission")
	}
	if g.broker.verifyChannelProcess(ctx, s.channel) != nil {
		return credentialPrivacyFailure("fence")
	}
	// The document may have navigated; channel/process identity must still be the
	// exact private source. Navigation evidence is obtained independently below.
	if g.controlCheck(ctx, p, s.source, s.channel, true, true) != nil {
		return credentialPrivacyFailure("fence")
	}
	return nil
}
func (g *Gateway) privacyExchange(ctx context.Context, p auth.Principal, s *credentialPrivacyState, kind string, expected Identity, newDocument bool) (Identity, error) {
	b, c := g.broker, s.channel
	if e := g.privacyChannel(ctx, p, s); e != nil {
		return Identity{}, e
	}
	var endBadge func()
	ctx, endBadge = b.beginControlBadge(ctx, c, expected)
	defer endBadge()
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	pending := &credentialPrivacyPending{requestID: newPrivateID(), attemptID: s.submitID, permitID: s.permitID, expected: expected, newDocument: newDocument, allowSameDocument: s.allowSameDocument, allowNavigation: kind == "credentialPrivacyVerify", done: make(chan Identity, 1)}
	b.mu.Lock()
	if c.conn != s.conn || b.closed || c.privacyPending != nil || len(c.pending) != 0 || len(c.unknown) != 0 || c.privateCredential != nil || c.privateAdvance != nil || c.lifecycleInhibited {
		b.mu.Unlock()
		return Identity{}, credentialPrivacyFailure("fence")
	}
	c.invalidateConsentReconnect()
	c.privacyPending = pending
	b.mu.Unlock()
	command := map[string]any{"type": kind, "requestId": pending.requestID, "attemptId": s.submitID, "identity": expected, "brokerEpoch": s.source.BrokerEpoch, "channelEpoch": s.source.ChannelEpoch, "scopeHash": s.source.ScopeHash, "controlLease": s.source.Lease, "deadlineUnixMs": deadline.UnixMilli(), "origin": s.source.Document.Origin, "permitId": s.permitID}
	c.writeMu.Lock()
	err := g.privacyChannel(ctx, p, s)
	if err == nil {
		err = s.conn.SetWriteDeadline(deadline)
	}
	if err == nil {
		err = WriteFrame(s.conn, command)
	}
	_ = s.conn.SetWriteDeadline(time.Time{})
	c.writeMu.Unlock()
	if err != nil {
		_ = s.conn.Close()
		var phase credentialPrivacyFailure
		if errors.As(err, &phase) {
			return Identity{}, phase
		}
		return Identity{}, credentialPrivacyFailure("fence")
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case identity := <-pending.done:
		b.mu.Lock()
		changed, notReady := pending.changed, pending.notReady
		valid := !pending.failed && identity.DocumentID != "" && c.conn == s.conn && c.privacyPending == pending && len(c.unknown) == 0
		if valid {
			c.privacyPending = nil
		}
		b.mu.Unlock()
		if !valid {
			_ = s.conn.Close()
			return Identity{}, credentialPrivacyFailure("reply")
		}
		if e := g.privacyChannel(ctx, p, s); e != nil {
			_ = s.conn.Close()
			return Identity{}, e
		}
		if notReady {
			return identity, credentialPrivacyFailure("notReady")
		}
		if changed {
			return identity, ErrCredentialPrivacyDocumentChanged
		}
		return identity, nil
	case <-ctx.Done():
		_ = s.conn.Close()
		return Identity{}, credentialPrivacyFailure("probe")
	case <-timer.C:
		_ = s.conn.Close()
		return Identity{}, credentialPrivacyFailure("probe")
	}
}

// QualifyCredentialPrivacy prepares and commits an independently qualified
// redacted document. The authenticated submit proof retires the private lease.
// Publication grants no dispatch lease; ordinary first use admits its own.
func (g *Gateway) QualifyCredentialPrivacy(ctx context.Context, p auth.Principal, a ControlAuthority, submitID string, admit func(context.Context) error) (CredentialPrivacyProof, error) {
	if g == nil || g.broker == nil || admit == nil || !fingerprintV2Hash.MatchString(submitID) {
		return CredentialPrivacyProof{}, credentialPrivacyFailure("admission")
	}
	g.privacyMu.Lock()
	b := g.broker
	c := g.controlChannel(a)
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if c == nil || !ok {
		g.privacyMu.Unlock()
		return CredentialPrivacyProof{}, credentialPrivacyFailure("admission")
	}
	b.mu.Lock()
	flow := c.privateFlow
	old := c.privacy
	initial := flow != nil && !flow.poisoned && flow.submitConfirmed && flow.submitAttempt == submitID && sameControl(flow.authority, a) && flow.binding == binding
	repeated := old != nil && old.published && old.submitID == submitID && old.binding == binding && old.source.Owner == p.Namespace && old.source.ClientID == p.ClientID && (sameControl(old.authority, a) || sameControl(old.source, a))
	if (!initial && !repeated) || c.conn == nil || c.privacyPending != nil || c.privateCredential != nil || c.privateAdvance != nil || len(c.pending) != 0 || len(c.unknown) != 0 {
		b.mu.Unlock()
		g.privacyMu.Unlock()
		return CredentialPrivacyProof{}, credentialPrivacyFailure("admission")
	}
	source := a
	previous := a.Document.Identity
	if repeated {
		source = old.source
		previous = old.identity
		old.active = false
	}
	s := &credentialPrivacyState{gateway: g, channel: c, conn: c.conn, source: source, binding: binding, submitID: submitID, permitID: newPrivateID(), identity: previous, admit: admit}
	// A previously published proof already independently established the exact
	// committed document. Refreshing that redactor needs no new login submit.
	s.allowSameDocument = initial && flow.sameDocumentPrivacy || repeated
	b.mu.Unlock()
	success, safelyUnavailable := false, false
	defer func() {
		if !success {
			b.mu.Lock()
			s.active = false
			if safelyUnavailable && old != nil && c.privacy == old && c.conn == s.conn {
				old.active = false
				old.changed = true
				old.identity = s.identity
			}
			b.mu.Unlock()
			if !safelyUnavailable {
				_ = s.conn.Close()
			}
		}
	}()
	identity, err := g.privacyExchange(ctx, p, s, "credentialPrivacy", previous, true)
	if err != nil {
		safelyUnavailable = err == credentialPrivacyFailure("notReady")
		g.privacyMu.Unlock()
		return CredentialPrivacyProof{}, err
	}
	s.identity = identity // Retain the independently bound document if commit reports not ready.
	identity, err = g.privacyExchange(ctx, p, s, "credentialPrivacyCommit", identity, false)
	if err != nil {
		safelyUnavailable = err == credentialPrivacyFailure("notReady")
		g.privacyMu.Unlock()
		if safelyUnavailable {
			return CredentialPrivacyProof{}, err
		}
		return CredentialPrivacyProof{}, credentialPrivacyFailure("commit")
	}
	g.controlMu.Lock()
	record := g.controlRecordLocked(source)
	if record != nil && !sameControl(*record.authority, source) && (!repeated || !sameControl(*record.authority, old.authority)) {
		g.controlMu.Unlock()
		g.privacyMu.Unlock()
		return CredentialPrivacyProof{}, credentialPrivacyFailure("promotion")
	}
	if repeated {
		oldRecord := g.controlRecordLocked(old.authority)
		if oldRecord != nil && !sameControl(*oldRecord.authority, old.authority) {
			g.controlMu.Unlock()
			g.privacyMu.Unlock()
			return CredentialPrivacyProof{}, credentialPrivacyFailure("promotion")
		}
	}
	g.clearControlLocked(source)
	if repeated {
		g.clearControlLocked(old.authority)
	}
	g.controlMu.Unlock()
	b.mu.Lock()
	if c.conn != s.conn || len(c.unknown) != 0 {
		b.mu.Unlock()
		g.privacyMu.Unlock()
		return CredentialPrivacyProof{}, credentialPrivacyFailure("promotion")
	}
	next := source
	next.Document.Identity = identity
	next.Document.Title = ""
	next.Document.TitleTruncated = false
	next.Document.TabHandle = next.Document.QualifiedTabID()
	next.Lease = Lease{}
	// Quarantined source document state is replaced only by scalar metadata.
	docs := []Document{}
	for _, d := range c.documents {
		if d.TabID != identity.TabID {
			docs = append(docs, d)
		}
	}
	c.documents = append(docs, next.Document)
	s.identity = identity
	s.authority = next
	s.active = true
	// Both private acknowledgements proved retirement and committed redaction.
	// Publish only this DOM/privacy capability. No ordinary lease is borrowed
	// speculatively; normal first use performs its own exact admission.
	s.published = true
	c.privacy = s
	c.privateFlow = nil
	c.privateInspection = nil
	b.mu.Unlock()
	g.privacyMu.Unlock()
	success = true
	return CredentialPrivacyProof{state: s}, nil
}
func (g *Gateway) VerifyCredentialPrivacy(ctx context.Context, p auth.Principal, proof CredentialPrivacyProof, surface model.Surface, mutation bool) error {
	if g == nil || g.broker == nil || proof.state == nil || proof.state.gateway != g {
		return errCredentialPrivacy
	}
	return g.verifyCredentialPrivacy(ctx, p, proof.state, surface, mutation)
}
func (g *Gateway) verifyCredentialPrivacy(ctx context.Context, p auth.Principal, s *credentialPrivacyState, surface model.Surface, mutation bool) error {
	g.privacyMu.Lock()
	defer g.privacyMu.Unlock()
	b, c := g.broker, s.channel
	b.mu.Lock()
	authoritySnapshot, identitySnapshot := s.authority, s.identity
	b.mu.Unlock()
	if surface.Kind != "web" || surface.Origin != s.source.Document.Origin || surface.BundleID != "" || surface.TabID != "" && surface.TabID != authoritySnapshot.Document.QualifiedTabID() && surface.TabID != strconv.Itoa(identitySnapshot.TabID) || !privacyActor(ctx, p, s, mutation) {
		return errCredentialPrivacy
	}
	b.mu.Lock()
	wasChanged := s.changed && c.privacy == s && s.published && c.conn == s.conn && privacyOperationIdleLocked(ctx, c, identitySnapshot)
	b.mu.Unlock()
	if wasChanged {
		if g.privacyChannel(ctx, p, s) != nil {
			return errCredentialPrivacy
		}
		return ErrCredentialPrivacyDocumentChanged
	}
	b.mu.Lock()
	valid := c.privacy == s && s.active && s.published && c.conn == s.conn && privacyOperationIdleLocked(ctx, c, identitySnapshot)
	expected := s.identity
	b.mu.Unlock()
	if !valid {
		return errCredentialPrivacy
	}
	// Login has already retired private input and committed the extension's
	// redactor. Ordinary operations perform their own document/lease admission;
	// do not interleave another private inspector into that admission.
	if err := g.privacyChannel(ctx, p, s); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, d := range c.documents {
		if d.ProfileChannel != expected.ProfileChannel || d.BrowserInstance != expected.BrowserInstance || d.TabID != expected.TabID || d.FrameID != 0 {
			continue
		}
		if d.Origin != s.source.Document.Origin || d.DocumentID != expected.DocumentID {
			return ErrCredentialPrivacyDocumentChanged
		}
		if d.Generation < expected.Generation {
			return errCredentialPrivacy
		}
		return nil
	}
	// Missing inventory grants no authority; the private status lane can
	// perform fresh qualification without replaying any credential input.
	return ErrCredentialPrivacyDocumentChanged
}

func (g *Gateway) guardCredentialPrivacy(ctx context.Context, p auth.Principal, c *channel, d Document, mutation bool) error {
	if err := g.broker.qualifyVisibilityUnknown(ctx, c); err != nil {
		return err
	}
	g.broker.mu.Lock()
	if scopeDisjointLocked(c, d.Identity) {
		g.broker.mu.Unlock()
		return nil
	}
	s := c.privacy
	var identity Identity
	if s != nil {
		identity = s.identity
	}
	private := c.privateInspection != nil || c.privateCredential != nil || c.privateAdvance != nil || c.privateFlow != nil
	g.broker.mu.Unlock()
	if s == nil {
		if private {
			return errCredentialPrivacy
		}
		return nil
	}
	if d.DocumentID != identity.DocumentID || d.TabID != identity.TabID || d.Origin != s.source.Document.Origin {
		return errCredentialPrivacy
	}
	return g.verifyCredentialPrivacy(ctx, p, s, model.Surface{Kind: "web", Origin: d.Origin, TabID: d.QualifiedTabID()}, mutation)
}
func (b *Broker) guardPrivacyCommand(ctx context.Context, c *channel, command Command, mutation bool) error {
	b.mu.Lock()
	if publicReadPermitLocked(ctx, c, command, mutation) != nil || scopeDisjointLocked(c, command.Identity) || !mutation && inactivePrivacyReplacementLocked(c) && reconnectTargetRetirementLocked(c, command) {
		b.mu.Unlock()
		return nil
	}
	s := c.privacy
	knownSourceRetirement := command.Action == "executor.retire" && !mutation && knownPressSourceRetirementLocked(c, command.Identity, command.ControlLease, b.epoch)
	var d Document
	for _, candidate := range c.documents {
		identity := candidate.Identity
		// Revoking an exact existing lease posts no input. DOM mutations within
		// the same document must not prevent retiring it. Navigation and every
		// other identity field remain exact; input commands retain strict matching.
		if command.Action == "executor.retire" && identity.Generation >= command.Identity.Generation {
			identity.Generation = command.Identity.Generation
		}
		if identity == command.Identity || playwrightOwnEffectIdentityLocked(ctx, c, command.Identity, identity, command.ControlLease) {
			d = candidate
			break
		}
	}
	b.mu.Unlock()
	if s == nil {
		return nil
	}
	if knownSourceRetirement {
		// Revocation posts no page input and never acquires successor DOM rights.
		// The original actor's current private admission still governs the request.
		p, e := auth.FromContext(ctx)
		if e != nil || !privacyActor(ctx, p, s, true) {
			return errCredentialPrivacy
		}
		b.mu.Lock()
		valid := c.privacy == s && c.conn == s.conn && s.active && s.published && s.identity == command.Identity && knownPressSourceRetirementLocked(c, command.Identity, command.ControlLease, b.epoch)
		b.mu.Unlock()
		if !valid {
			return errCredentialPrivacy
		}
		return nil
	}
	if command.Action == "browser.navigate" {
		destination, ok := command.Args["url"].(string)
		origin, e := model.NavigationOrigin(destination)
		if !ok || e != nil || origin != s.source.Document.Origin {
			return errCredentialPrivacy
		}
	}
	switch command.Action {
	case "observe", "resolve", "read", "element.press", "element.fill", "browser.navigate", "browser.activate", "executor.acquire", "executor.validate", "executor.retire", "receipt.query":
	default:
		return errCredentialPrivacy
	}
	p, e := auth.FromContext(ctx)
	if e != nil || d.DocumentID == "" {
		return errCredentialPrivacy
	}
	return s.gateway.guardCredentialPrivacy(ctx, p, c, d, mutation)
}
