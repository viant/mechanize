package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// Trusted Host persistence only. This binds exposure scope, never input authority.
type CredentialProtectionScope struct {
	PreparationID    string   `json:"preparationId"`
	Identity         Identity `json:"identity"`
	Origin           string   `json:"origin"`
	LoginRouteSHA256 string   `json:"loginRouteSHA256"`
	ChromeStartToken string   `json:"chromeStartToken"`
	BrokerEpoch      string   `json:"brokerEpoch"`
	ChannelEpoch     string   `json:"channelEpoch"`
	ScopeHash        string   `json:"scopeHash"`
}
type credentialScopeFailure string

func (e credentialScopeFailure) Error() string { return string(e) }
func CredentialProtectionFailureReason(err error) string {
	var e credentialScopeFailure
	if errors.As(err, &e) {
		return string(e)
	}
	return "scopeUnavailable"
}
func scopeFailure(code string) error {
	switch code {
	case "scopeChanged", "scopeSourcePresent", "scopeTargetProtected", "scopeInventoryUnavailable", "scopeLimit", "scopeUnsupported", "scopePreflightBusy":
		return credentialScopeFailure(code)
	}
	return credentialScopeFailure("scopeUnavailable")
}
func validProtectionScope(s CredentialProtectionScope) bool {
	return fingerprintV2Hash.MatchString(s.PreparationID) && s.Identity.TabID > 0 && s.Identity.FrameID == 0 && s.Identity.DocumentID != "" && s.Identity.ProfileChannel != "" && s.Identity.BrowserInstance != "" && s.Identity.Generation > 0 && OrdinaryWebsiteOrigin(s.Origin) && strings.HasPrefix(s.Origin, "https://") && s.ChromeStartToken != "" && (s.LoginRouteSHA256 == "" || fingerprintV2Hash.MatchString(s.LoginRouteSHA256))
}

type credentialScopeRequest struct {
	Type             string   `json:"type"`
	RequestID        string   `json:"requestId"`
	Mode             string   `json:"mode"`
	PreparationID    string   `json:"preparationId"`
	SourceIdentity   Identity `json:"sourceIdentity"`
	SourceOrigin     string   `json:"sourceOrigin"`
	LoginRouteSHA256 string   `json:"loginRouteSHA256"`
	BrokerEpoch      string   `json:"brokerEpoch"`
	ChannelEpoch     string   `json:"channelEpoch"`
	ScopeHash        string   `json:"scopeHash"`
	DeadlineUnixMS   int64    `json:"deadlineUnixMs"`
	TargetTabID      int      `json:"targetTabId"`
	TargetOrigin     string   `json:"targetOrigin"`
	ControlLease     *Lease   `json:"controlLease,omitempty"`
}

// ScopeTargetMetadata is a browser-owned routing sample, never a Document or
// input authority. Unknown renderer generation is absent, not invented.
type ScopeTargetMetadata struct {
	ProfileChannel  string  `json:"profileChannel"`
	BrowserInstance string  `json:"browserInstance"`
	TabID           int     `json:"tabId"`
	FrameID         int     `json:"frameId"`
	DocumentID      string  `json:"documentId"`
	Generation      *uint64 `json:"documentGeneration,omitempty"`
}
type credentialScopeReply struct {
	Type             string                    `json:"type"`
	RequestID        string                    `json:"requestId"`
	BrokerEpoch      string                    `json:"brokerEpoch"`
	ChannelEpoch     string                    `json:"channelEpoch"`
	ScopeHash        string                    `json:"scopeHash"`
	Ready            bool                      `json:"ready"`
	Reason           string                    `json:"reason"`
	LoginRouteSHA256 string                    `json:"loginRouteSHA256"`
	TargetIdentity   *ScopeTargetMetadata      `json:"targetIdentity"`
	PublicDocument   *credentialPublicDocument `json:"publicDocument,omitempty"`
}
type credentialScopePending struct {
	request credentialScopeRequest
	conn    net.Conn
	done    chan credentialScopeReply
}

func (b *Broker) acceptCredentialScopeLocked(c *channel, conn net.Conn, raw []byte) bool {
	var kind struct{ Type string }
	if json.Unmarshal(raw, &kind) != nil || kind.Type != "credentialScopeResult" {
		return false
	}
	defer clear(raw)
	p := c.protectionPending
	if p == nil || p.conn != conn || c.conn != conn || len(raw) > 4096 {
		return true
	}
	var r credentialScopeReply
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF {
		return true
	}
	encoded, _ := json.Marshal(r)
	q := p.request
	if !bytes.Equal(raw, encoded) || r.RequestID != q.RequestID || r.BrokerEpoch != q.BrokerEpoch || r.ChannelEpoch != q.ChannelEpoch || r.ScopeHash != q.ScopeHash || time.Now().UnixMilli() > q.DeadlineUnixMS {
		return true
	}
	if r.PublicDocument != nil && (q.Mode != "publicRead" || !r.Ready) {
		return true
	}
	if r.Ready {
		if r.Reason != "none" {
			return true
		}
	} else if r.Reason == "none" || CredentialProtectionFailureReason(scopeFailure(r.Reason)) != r.Reason || r.TargetIdentity != nil || r.LoginRouteSHA256 != "" {
		return true
	}
	select {
	case p.done <- r:
	default:
	}
	return true
}
func (g *Gateway) CaptureCredentialProtectionScope(ctx context.Context, p auth.Principal, a ControlAuthority, preparationID string) (CredentialProtectionScope, error) {
	s := CredentialProtectionScope{PreparationID: preparationID, Identity: a.Document.Identity, Origin: a.Document.Origin, ChromeStartToken: a.Evidence.ChromeParent.StartToken, BrokerEpoch: a.BrokerEpoch, ChannelEpoch: a.ChannelEpoch, ScopeHash: a.ScopeHash}
	if !validProtectionScope(s) || g.VerifyControl(ctx, p, a) != nil {
		return CredentialProtectionScope{}, scopeFailure("scopeChanged")
	}
	r, e := g.credentialScopeExchange(ctx, p, s, "capture", 0, "", &a.Lease)
	if e != nil {
		return CredentialProtectionScope{}, e
	}
	if !fingerprintV2Hash.MatchString(r.LoginRouteSHA256) || r.TargetIdentity != nil || g.VerifyControl(ctx, p, a) != nil {
		return CredentialProtectionScope{}, scopeFailure("scopeChanged")
	}
	s.LoginRouteSHA256 = r.LoginRouteSHA256
	g.broker.mu.Lock()
	c := g.broker.channels[channelKey(s.Identity.ProfileChannel, s.Identity.BrowserInstance)]
	if c.protectionSources == nil {
		c.protectionSources = map[string]CredentialProtectionScope{}
	}
	c.protectionSources[s.PreparationID] = s
	g.broker.mu.Unlock()
	return s, nil
}
func (g *Gateway) VerifyCredentialScopeAbsent(ctx context.Context, p auth.Principal, s CredentialProtectionScope) error {
	if !validProtectionScope(s) || authorize(ctx, p, true) != nil {
		return scopeFailure("scopeChanged")
	}
	actual, _ := auth.FromContext(ctx)
	if actual.ClientID != p.ClientID {
		return auth.ErrUnauthorized
	}
	b := g.broker
	b.mu.Lock()
	c := b.channels[channelKey(s.Identity.ProfileChannel, s.Identity.BrowserInstance)]
	sameBirth := c != nil && c.conn != nil && c.processEvidence != nil && c.processEvidence.ChromeParent.StartToken == s.ChromeStartToken
	b.mu.Unlock()
	if !sameBirth {
		if session.VerifyProcessBirthAbsent(ctx, uint32(os.Getuid()), s.ChromeStartToken) == nil {
			return nil
		}
		return scopeFailure("scopeChanged")
	}
	r, e := g.credentialScopeExchange(ctx, p, s, "absent", 0, "", nil)
	if e != nil {
		return e
	}
	if r.TargetIdentity != nil || r.LoginRouteSHA256 != "" {
		return scopeFailure("scopeChanged")
	}
	return nil
}

// RetireAbsentCredentialScope releases only dead-source live control after the
// Host durably retires exposure protection. Attempts and receipts are retained.
func (g *Gateway) RetireAbsentCredentialScope(ctx context.Context, p auth.Principal, s CredentialProtectionScope) error {
	if e := g.VerifyCredentialScopeAbsent(ctx, p, s); e != nil {
		return e
	}
	b := g.broker
	b.mu.Lock()
	c := b.channels[channelKey(s.Identity.ProfileChannel, s.Identity.BrowserInstance)]
	connected := c != nil && c.conn != nil
	b.mu.Unlock()
	if connected {
		if _, e := g.credentialScopeExchange(ctx, p, s, "retire", 0, "", nil); e != nil {
			return e
		}
	}
	g.controlMu.Lock()
	defer g.controlMu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	same := func(i Identity) bool {
		return i.ProfileChannel == s.Identity.ProfileChannel && i.BrowserInstance == s.Identity.BrowserInstance && i.TabID == s.Identity.TabID && i.DocumentID == s.Identity.DocumentID
	}
	if c != nil {
		if c.privateCredential != nil || c.privateAdvance != nil || c.privacyPending != nil || len(c.pending) > 0 {
			return scopeFailure("scopeChanged")
		}
		if c.privateInspection != nil && same(c.privateInspection.identity) {
			c.privateInspection = nil
		}
		if c.privateFlow != nil && same(c.privateFlow.authority.Document.Identity) {
			c.privateFlow = nil
		}
		if c.privacy != nil && same(c.privacy.identity) {
			c.privacy = nil
		}
	}
	if c != nil {
		delete(c.protectionSources, s.PreparationID)
		retained := c.documents[:0]
		for _, d := range c.documents {
			if !same(d.Identity) {
				retained = append(retained, d)
			}
		}
		c.documents = retained
	}
	if g.control != nil && same(g.control.Document.Identity) {
		if g.controlRetiring {
			return scopeFailure("scopeChanged")
		}
		g.control = nil
	}
	return nil
}
func (g *Gateway) VerifyProtectionDisjoint(ctx context.Context, p auth.Principal, s CredentialProtectionScope, target model.Surface) error {
	if authorize(ctx, p, false) != nil || target.Kind != "web" || !OrdinaryWebsiteOrigin(target.Origin) || !OrdinaryWebsiteOrigin(s.Origin) || target.BundleID != "" || target.ProcessID != 0 || target.ProcessStartToken != "" || target.Title != "" {
		return scopeFailure("scopeChanged")
	}
	actual, _ := auth.FromContext(ctx)
	if actual.ClientID != p.ClientID {
		return auth.ErrUnauthorized
	}
	c, d, e := g.broker.selectDocument(p, target)
	if e != nil {
		return scopeFailure("scopeTargetProtected")
	}
	if g.broker.checkChannelProcess(ctx, c, false) != nil {
		return scopeFailure("scopeChanged")
	}
	if target.Origin != s.Origin || d.ProfileChannel != s.Identity.ProfileChannel || d.BrowserInstance != s.Identity.BrowserInstance {
		// Missing legacy identity is not a proof of same-origin disjointness.
		if target.Origin == s.Origin && !validProtectionScope(s) {
			return scopeFailure("scopeTargetProtected")
		}
		g.broker.mu.Lock()
		birth := ""
		if c.processEvidence != nil {
			birth = c.processEvidence.ChromeParent.StartToken
		}
		g.broker.mu.Unlock()
		targetScope := CredentialProtectionScope{PreparationID: strings.Repeat("0", 64), Identity: d.Identity, Origin: d.Origin, ChromeStartToken: birth}
		r, e := g.credentialScopeExchange(ctx, p, targetScope, "target", d.TabID, d.Origin, nil)
		if e != nil {
			return e
		}
		if r.TargetIdentity == nil || r.TargetIdentity.DocumentID != d.DocumentID || r.TargetIdentity.TabID != d.TabID {
			return scopeFailure("scopeChanged")
		}
		return nil
	}
	if !validProtectionScope(s) || d.TabID == s.Identity.TabID {
		return scopeFailure("scopeTargetProtected")
	}
	r, e := g.credentialScopeExchange(ctx, p, s, "disjoint", d.TabID, target.Origin, nil)
	if e != nil {
		return e
	}
	if r.TargetIdentity == nil || r.TargetIdentity.DocumentID != d.DocumentID || r.TargetIdentity.TabID != d.TabID || r.TargetIdentity.FrameID != 0 || r.TargetIdentity.ProfileChannel != d.ProfileChannel || r.TargetIdentity.BrowserInstance != d.BrowserInstance {
		return scopeFailure("scopeChanged")
	}
	return nil
}

func (g *Gateway) credentialScopeExchange(ctx context.Context, p auth.Principal, s CredentialProtectionScope, mode string, targetTab int, targetOrigin string, lease *Lease) (credentialScopeReply, error) {
	empty := credentialScopeReply{}
	if g == nil || g.broker == nil || authorize(ctx, p, false) != nil {
		return empty, scopeFailure("scopeChanged")
	}
	timeout := 2 * time.Second
	if mode == "publicRead" {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	b := g.broker
	b.mu.Lock()
	c := b.channels[channelKey(s.Identity.ProfileChannel, s.Identity.BrowserInstance)]
	if c == nil || c.conn == nil || c.fixtureOnly || c.grant.Principal.Namespace != p.Namespace || !allowedOrigin(c.grant, s.Origin) || !channelScopeQualified(c) {
		b.mu.Unlock()
		return empty, scopeFailure("scopeChanged")
	}
	if c.protectionScopeVersion != 1 || mode == "publicRead" && c.credentialPublicReadVersion != 1 && c.credentialPublicReadVersion != 2 {
		b.mu.Unlock()
		return empty, scopeFailure("scopeUnsupported")
	}
	b.mu.Unlock()
	if b.checkCredentialScopeProcess(ctx, c) != nil {
		return empty, scopeFailure("scopeChanged")
	}
	deadline, _ := ctx.Deadline()
	b.mu.Lock()
	if c.conn == nil || c.protectionPending != nil || b.closed {
		b.mu.Unlock()
		return empty, scopeFailure("scopeChanged")
	}
	pending := &credentialScopePending{request: credentialScopeRequest{Type: "credentialScope", RequestID: newID() + newID(), Mode: mode, PreparationID: s.PreparationID, SourceIdentity: s.Identity, SourceOrigin: s.Origin, LoginRouteSHA256: s.LoginRouteSHA256, BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, DeadlineUnixMS: deadline.UnixMilli(), TargetTabID: targetTab, TargetOrigin: targetOrigin, ControlLease: lease}, conn: c.conn, done: make(chan credentialScopeReply, 1)}
	c.protectionPending = pending
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		if c.protectionPending == pending {
			c.protectionPending = nil
		}
		b.mu.Unlock()
	}()
	written := make(chan error, 1)
	go func() {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		if ctx.Err() != nil {
			written <- ctx.Err()
			return
		}
		pending.conn.SetWriteDeadline(deadline)
		err := WriteFrame(pending.conn, pending.request)
		pending.conn.SetWriteDeadline(time.Time{})
		written <- err
	}()
	select {
	case e := <-written:
		if e != nil {
			return empty, scopeFailure("scopeUnavailable")
		}
	case <-ctx.Done():
		return empty, scopeFailure("scopeUnavailable")
	}
	var r credentialScopeReply
	select {
	case r = <-pending.done:
	case <-ctx.Done():
		return empty, scopeFailure("scopeUnavailable")
	}
	if b.checkCredentialScopeProcess(ctx, c) != nil {
		return empty, scopeFailure("scopeChanged")
	}
	b.mu.Lock()
	same := c.conn == pending.conn && c.epoch == pending.request.ChannelEpoch && c.scopeHash == pending.request.ScopeHash && b.epoch == pending.request.BrokerEpoch && !b.closed && channelScopeQualified(c)
	b.mu.Unlock()
	if !same {
		return empty, scopeFailure("scopeChanged")
	}
	if !r.Ready {
		return empty, scopeFailure(r.Reason)
	}
	return r, nil
}
