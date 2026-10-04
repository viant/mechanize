package host

import (
	"context"
	"errors"
	"strconv"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
)

// Private provider capability. Production closes over an actual opaque Chrome
// ReadBinding captured during the original control admission. Neither a plan,
// proposed postcondition nor native-host hello can construct this capability.
type webPostconditionRead struct {
	identity chrome.ReadProof
	read     func(context.Context, auth.Principal, model.Selector, string) (model.Value, chrome.ReadProof, error)
}

func pinnedWebPostconditionRead(gateway *chrome.Gateway, pin chrome.ReadBinding) *webPostconditionRead {
	return &webPostconditionRead{identity: pin.Identity(), read: func(ctx context.Context, p auth.Principal, target model.Selector, attribute string) (model.Value, chrome.ReadProof, error) {
		return gateway.ReadPinned(ctx, p, pin, target, attribute, nil)
	}}
}
func (read *webPostconditionRead) validate(p auth.Principal, a WebControlAuthority) error {
	if read == nil || read.read == nil || read.identity.Owner != p.Namespace || read.identity.ClientID != p.ClientID || read.identity.ExtensionOrigin != a.ExtensionOrigin || read.identity.BrokerEpoch != a.BrokerEpoch || read.identity.ChannelEpoch != a.ChannelEpoch || read.identity.ScopeHash != a.ScopeHash || read.identity.Document != a.Document {
		return ErrWebControlUnqualified
	}
	return nil
}
func webIdentity(proof chrome.ReadProof) objective.WebIdentity {
	d := proof.Document
	return objective.WebIdentity{ProfileChannel: d.ProfileChannel, BrowserInstance: d.BrowserInstance, Origin: d.Origin, TabID: d.TabID, FrameID: d.FrameID, DocumentID: d.DocumentID, Generation: d.Generation, ExtensionOrigin: proof.ExtensionOrigin, BrokerEpoch: proof.BrokerEpoch, ChannelEpoch: proof.ChannelEpoch, ScopeHash: proof.ScopeHash}
}
func sameWebPostconditionIdentity(a, b objective.WebIdentity) bool {
	a.Generation = 0
	b.Generation = 0
	return a == b
}

// Derivation reads only the capability retained by this exact step context.
// Origin is a constraint on that pin, never a document-selection request.
func (h *Host) resolveWebPostconditionIdentity(ctx context.Context, p auth.Principal, origin string) (objective.WebIdentity, error) {
	_, reader, err := h.heldWebPostconditionRead(ctx, p, origin)
	if err != nil {
		return objective.WebIdentity{}, err
	}
	id := webIdentity(reader.identity)
	if id.FrameID != 0 || id.Generation == 0 {
		return objective.WebIdentity{}, ErrWebControlUnqualified
	}
	return id, nil
}

func (h *Host) heldWebPostconditionRead(ctx context.Context, p auth.Principal, origin string) (*webControlIntent, *webPostconditionRead, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
		return nil, nil, auth.ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	user, err := h.authorize(ctx, actual)
	if err != nil {
		return nil, nil, err
	}
	permitted := user.DesktopAccess
	for _, allowed := range user.WebOrigins {
		permitted = permitted || allowed == origin
	}
	if !permitted {
		return nil, nil, auth.ErrUnauthorized
	}
	intent, ok := ctx.Value(webControlIntentKey{}).(*webControlIntent)
	meta, hasMeta := automation.ExecutionFromContext(ctx)
	binding, hasBinding := auth.ConsentBindingFromContext(ctx)
	if !ok || intent == nil || h.webControl == nil || intent.manager != h.webControl || !hasMeta || !hasBinding || intent.metadata != meta || intent.binding != binding || intent.principal.Namespace != actual.Namespace || intent.principal.ClientID != actual.ClientID {
		return nil, nil, ErrWebControlIntent
	}
	manager := intent.manager
	manager.mu.Lock()
	ready := intent.readReady && intent.dispatched && !manager.closed && manager.options.Owner.Err() == nil && !manager.inhibited[webChannelKey(intent.authority)]
	reader := intent.postconditionRead
	manager.mu.Unlock()
	if !ready || reader == nil || manager.options.authorizeRead == nil {
		return nil, nil, errors.New("original dispatched and retired web read admission unavailable")
	}
	if err := reader.validate(actual, intent.authority); err != nil {
		return nil, nil, err
	}
	if reader.identity.Document.Origin != origin {
		return nil, nil, errors.New("web predicate differs from original admitted document binding")
	}
	return intent, reader, nil
}

func (h *Host) readWebPredicate(ctx context.Context, p auth.Principal, target model.Selector, attribute string, expected objective.WebIdentity) (model.Value, objective.WebEvidence, error) {
	failure := func(err error) (model.Value, objective.WebEvidence, error) {
		return model.Value{}, objective.WebEvidence{}, err
	}
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
		return failure(auth.ErrUnauthorized)
	}
	p = actual
	if target.Surface.Kind != "web" || target.Surface.Origin != expected.Origin || target.Surface.TabID != expected.ProfileChannel+"/"+expected.BrowserInstance+"/"+strconv.Itoa(expected.TabID) || expected.FrameID != 0 {
		return failure(auth.ErrUnauthorized)
	}
	intent, reader, err := h.heldWebPostconditionRead(ctx, p, target.Surface.Origin)
	if err != nil {
		return failure(err)
	}
	manager, meta, binding := intent.manager, intent.metadata, intent.binding
	if !sameWebPostconditionIdentity(expected, webIdentity(reader.identity)) || expected.Generation == 0 {
		return failure(errors.New("web predicate differs from original admitted document binding"))
	}
	lease, err := manager.options.authorizeRead(ctx, p, target.Surface)
	if err != nil {
		return failure(err)
	}
	if lease == nil || lease.Context == nil || lease.Release == nil {
		return failure(auth.ErrUnauthorized)
	}
	defer lease.Release()
	leasePrincipal, principalErr := auth.FromContext(lease.Context)
	leaseMeta, metaOK := automation.ExecutionFromContext(lease.Context)
	leaseBinding, bindingOK := auth.ConsentBindingFromContext(lease.Context)
	if principalErr != nil || leasePrincipal.Namespace != p.Namespace || leasePrincipal.ClientID != p.ClientID || !metaOK || leaseMeta != meta || !bindingOK || leaseBinding != binding {
		return failure(auth.ErrUnauthorized)
	}
	value, proof, err := reader.read(lease.Context, p, target, attribute)
	if contextErr := lease.Context.Err(); contextErr != nil {
		return failure(contextErr)
	}
	if err == nil && (value.Kind != model.StringValue || value.String == "[redacted]") {
		return failure(errors.New("protected web read unavailable"))
	}
	if err != nil {
		return failure(err)
	}
	if proof.Owner != p.Namespace || proof.ClientID != p.ClientID || !sameWebPostconditionIdentity(webIdentity(proof), expected) || proof.Document.Generation < expected.Generation || proof.RequestID == "" || proof.StartedAt.IsZero() || proof.ReturnedAt.Before(proof.StartedAt) {
		return failure(errors.New("actual web read proof does not match original document"))
	}
	return value, objective.WebEvidence{Owner: proof.Owner, ClientID: proof.ClientID, Identity: webIdentity(proof), RequestID: proof.RequestID, ObservedAt: proof.ReturnedAt}, nil
}
