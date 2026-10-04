package chrome

import (
	"context"
	"errors"
	"strconv"
	"time"
	"unicode/utf16"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
)

// ReadBinding is an opaque in-process pin to one admitted document and signed
// channel. Capture before mutation; a retired mutation lease cannot erase it.
// No wire field can construct this binding or turn it into dispatch authority.
type ReadBinding struct {
	broker                                                                 *Broker
	channel                                                                *channel
	owner, clientID, extensionOrigin, brokerEpoch, channelEpoch, scopeHash string
	trustScope                                                             string
	scopeQualified                                                         bool
	document                                                               Document
	nativeHost, chromeParent                                               session.ProcessIdentity
}

// ReadProof contains actual read-reply identity and broker-observed timing. It
// deliberately contains no read value, mutation receipt or business success.
type ReadProof struct {
	TrustScope      string    `json:"trustScope"`
	ScopeQualified  bool      `json:"scopeQualified"`
	Owner           string    `json:"owner"`
	ClientID        string    `json:"clientId"`
	ExtensionOrigin string    `json:"extensionOrigin"`
	BrokerEpoch     string    `json:"brokerEpoch"`
	ChannelEpoch    string    `json:"channelEpoch"`
	ScopeHash       string    `json:"scopeHash"`
	Document        Document  `json:"document"`
	RequestID       string    `json:"requestId"`
	StartedAt       time.Time `json:"startedAt"`
	ReturnedAt      time.Time `json:"returnedAt"`
}

// Identity returns detached metadata for the opaque pin; it does not prove a read.
func (p ReadBinding) Identity() ReadProof {
	return ReadProof{TrustScope: p.trustScope, ScopeQualified: p.scopeQualified, Owner: p.owner, ClientID: p.clientID, ExtensionOrigin: p.extensionOrigin, BrokerEpoch: p.brokerEpoch, ChannelEpoch: p.channelEpoch, ScopeHash: p.scopeHash, Document: p.document}
}
func sameReadDocument(a, b Document) bool {
	return a.ProfileChannel == b.ProfileChannel && a.BrowserInstance == b.BrowserInstance && a.TabID == b.TabID && a.FrameID == b.FrameID && a.DocumentID == b.DocumentID && a.Origin == b.Origin
}
func (g *Gateway) captureReadBinding(ctx context.Context, p auth.Principal, c *channel, d Document) (ReadBinding, error) {
	if err := authorize(ctx, p, false); err != nil {
		return ReadBinding{}, err
	}
	actual, _ := auth.FromContext(ctx)
	if actual.ClientID != p.ClientID {
		return ReadBinding{}, auth.ErrUnauthorized
	}
	if c == nil {
		return ReadBinding{}, auth.ErrUnauthorized
	}
	if err := g.broker.verifyChannelProcess(ctx, c); err != nil {
		return ReadBinding{}, err
	}
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	if c == nil || c.fixtureOnly || c.conn == nil || g.broker.closed || c.processEvidence == nil || !c.processEvidence.KernelPeerQualified || !channelScopeQualified(c) || !c.executorQualified || !c.inventoryComplete || c.grant.Principal.Namespace != p.Namespace || d.FrameID != 0 || d.TabID <= 0 || d.DocumentID == "" || d.Generation == 0 || !allowedOrigin(c.grant, d.Origin) {
		return ReadBinding{}, browserError("readUnqualified", "Exact live signed root-document channel required", "notDispatched")
	}
	matches := 0
	for _, current := range c.documents {
		if sameReadDocument(current, d) && current.Generation >= d.Generation {
			matches++
		}
	}
	if matches != 1 {
		return ReadBinding{}, browserError("staleIdentity", "Exact original document unavailable", "notDispatched")
	}
	return ReadBinding{trustScope: c.grant.TrustScope, scopeQualified: channelScopeQualified(c), broker: g.broker, channel: c, owner: p.Namespace, clientID: p.ClientID, extensionOrigin: c.grant.ExtensionOrigin, brokerEpoch: g.broker.epoch, channelEpoch: c.epoch, scopeHash: c.scopeHash, document: d, nativeHost: c.processEvidence.NativeHost, chromeParent: c.processEvidence.ChromeParent}, nil
}

// PinReadDocument selects once for a standalone read. For a mutation's later
// postcondition use PinControlRead during its actual original control admission.
func (g *Gateway) PinReadDocument(ctx context.Context, p auth.Principal, surface model.Surface) (ReadBinding, error) {
	if err := authorize(ctx, p, false); err != nil {
		return ReadBinding{}, err
	}
	c, d, err := g.broker.selectDocument(p, surface)
	if err != nil {
		return ReadBinding{}, err
	}
	return g.captureReadBinding(ctx, p, c, d)
}
func (g *Gateway) PinControlRead(ctx context.Context, p auth.Principal, a ControlAuthority) (ReadBinding, error) {
	if err := g.VerifyControl(ctx, p, a); err != nil {
		return ReadBinding{}, err
	}
	c := g.controlChannel(a)
	if c == nil {
		return ReadBinding{}, auth.ErrUnauthorized
	}
	return g.captureReadBinding(ctx, p, c, a.Document)
}
func (g *Gateway) checkReadBinding(ctx context.Context, p auth.Principal, pin ReadBinding) (Document, error) {
	if err := authorize(ctx, p, false); err != nil {
		return Document{}, err
	}
	actual, _ := auth.FromContext(ctx)
	if pin.broker != g.broker || pin.channel == nil || pin.owner != p.Namespace || pin.clientID != p.ClientID || actual.ClientID != pin.clientID {
		return Document{}, auth.ErrUnauthorized
	}
	if err := g.broker.verifyChannelProcess(ctx, pin.channel); err != nil {
		return Document{}, err
	}
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	c := pin.channel
	if c.fixtureOnly || c.conn == nil || g.broker.closed || c.processEvidence == nil || !c.processEvidence.KernelPeerQualified || !channelScopeQualified(c) || !pin.scopeQualified || pin.trustScope != c.grant.TrustScope || !c.executorQualified || !c.inventoryComplete || c.grant.Principal.Namespace != pin.owner || g.broker.epoch != pin.brokerEpoch || c.epoch != pin.channelEpoch || c.scopeHash != pin.scopeHash || c.grant.ExtensionOrigin != pin.extensionOrigin || c.processEvidence.NativeHost != pin.nativeHost || c.processEvidence.ChromeParent != pin.chromeParent {
		return Document{}, browserError("staleIdentity", "Original signed document channel changed", "notDispatched")
	}
	var found Document
	matches := 0
	for _, d := range c.documents {
		if sameReadDocument(d, pin.document) && d.Generation >= pin.document.Generation {
			found = d
			matches++
		}
	}
	if matches != 1 {
		return Document{}, browserError("staleIdentity", "Original root document replaced or unavailable", "notDispatched")
	}
	return found, ctx.Err()
}

// ReadPinned observes the latest generation inside the same exact document,
// then performs one independently protected read. It never reselects by origin,
// acquires a mutation lease, executes scripts, or confirms a dispatch receipt.
func (g *Gateway) ReadPinned(ctx context.Context, p auth.Principal, pin ReadBinding, target model.Selector, attribute string, values map[string]model.Value) (model.Value, ReadProof, error) {
	failure := func(err error) (model.Value, ReadProof, error) { return model.Value{}, ReadProof{}, err }
	if attribute != "value" && attribute != "text" && attribute != "name" {
		return failure(browserError("unsupportedAttribute", "Protected web read supports value, text and name", "notDispatched"))
	}
	if err := target.Validate(); err != nil {
		return failure(err)
	}
	surface := target.Surface
	if surface.Kind != "web" || surface.BundleID != "" || surface.ValidateProcessIdentity() != nil || surface.Origin != pin.document.Origin || surface.TabID == "" || (surface.TabID != pin.document.QualifiedTabID() && surface.TabID != strconv.Itoa(pin.document.TabID)) {
		return failure(auth.ErrUnauthorized)
	}
	locator, err := compileLocator(target, values)
	if err != nil {
		return failure(err)
	}
	d, err := g.checkReadBinding(ctx, p, pin)
	if err != nil {
		return failure(err)
	}
	if surface.Title != "" && (d.TitleTruncated || surface.Title != d.Title) {
		return failure(browserError("staleIdentity", "Pinned document title constraint changed", "notDispatched"))
	}
	check := func() error { _, err := g.checkReadBinding(ctx, p, pin); return err }
	observed, err := g.broker.call(ctx, pin.channel, Command{Action: "observe", Identity: d.Identity, Args: map[string]any{"limit": 1}}, false, check)
	if err != nil {
		return failure(err)
	}
	if !sameReadDocument(Document{Identity: observed.Identity, Origin: d.Origin}, pin.document) || observed.Identity.Generation < d.Generation {
		return failure(browserError("receiptMismatch", "Pinned observation identity mismatch", "notDispatched"))
	}
	if _, err = g.checkReadBinding(ctx, p, pin); err != nil {
		return failure(err)
	}
	started := time.Now()
	reply, err := g.broker.call(ctx, pin.channel, Command{Action: "read", Identity: observed.Identity, Locator: locator, Args: map[string]any{"attribute": attribute}}, false, check)
	returned := time.Now()
	if err != nil {
		return failure(err)
	}
	if _, err = g.checkReadBinding(ctx, p, pin); err != nil {
		return failure(err)
	}
	if reply.RequestID == "" || !sameReadDocument(Document{Identity: reply.Identity, Origin: d.Origin}, pin.document) || reply.Identity.Generation < observed.Identity.Generation {
		return failure(browserError("receiptMismatch", "Actual protected read identity mismatch", "notDispatched"))
	}
	if reply.Value == nil || *reply.Value == "[redacted]" {
		return failure(browserError("attributeUnavailable", "Protected web read unavailable or redacted", "notDispatched"))
	}
	// The current DOM protocol normalizes whitespace and slices strings at 256
	// UTF-16 units without a truncation flag. Never confirm equality at that boundary.
	if len(utf16.Encode([]rune(*reply.Value))) >= 256 {
		return failure(browserError("readCoverageUnknown", "Web read reached its unqualified truncation boundary", "notDispatched"))
	}
	proof := pin.Identity()
	proof.Document = d
	proof.Document.Identity = reply.Identity
	proof.RequestID = reply.RequestID
	proof.StartedAt = started
	proof.ReturnedAt = returned
	value := model.Value{Kind: model.StringValue, String: *reply.Value}
	if err := value.Validate(); err != nil {
		return failure(errors.New("invalid protected web read value"))
	}
	return value, proof, nil
}
