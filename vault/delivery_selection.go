package vault

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/viant/mechanize/auth"
)

// DeliveryRecipient contains only independently pinned browser routing. Account,
// Vault reference and ciphertext revision stay inside the opaque selection.
type DeliveryRecipient struct{ SessionID, DocumentID, NavigationID, Origin string }
type DeliverySelection struct{ state *deliverySelectionState }
type deliverySelectionState struct {
	mu                  sync.Mutex
	store               *Store
	namespace, clientID string
	consent             auth.ConsentBinding
	binding             Binding
	metadata            EntryMetadata
	expires             time.Time
	authorize           func(context.Context) error
	revoked, busy       bool
}

func (DeliverySelection) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }
func (DeliverySelection) String() string               { return "[private credential selection withheld]" }
func (DeliverySelection) GoString() string             { return "[private credential selection withheld]" }
func (DeliverySelection) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private credential selection withheld]")
}

// NewDeliverySelection belongs only to the trusted host after native transport
// authentication. It never creates NativeHuman authority. The original verified
// automation actor, not the native selector, owns subsequent consent and use.
// Store.Metadata authenticates locally (internally decrypting and wiping); the
// selector never receives or returns username/password values.
func NewDeliverySelection(nativeCtx, automationCtx context.Context, store *Store, binding Binding, metadata EntryMetadata, expires time.Time, authorize func(context.Context) error) (selection *DeliverySelection, err error) {
	defer func() {
		if recover() != nil {
			selection = nil
			err = ErrUnavailable
		}
	}()
	native, e := auth.FromContext(nativeCtx)
	actor, ae := auth.FromContext(automationCtx)
	consent, ok := auth.ConsentBindingFromContext(automationCtx)
	if e != nil || ae != nil || native.Validate() != nil || actor.Validate() != nil || !auth.NativeHuman(nativeCtx) || !native.HasScope("consent:admin") || native.ClientID == "" || native.Namespace != actor.Namespace || actor.ClientID == "" || !actor.HasScope("desktop:control") || !ok || consent.SessionID != binding.SessionID || consent.GrantID == "" || consent.Purpose == "" {
		return nil, auth.ErrUnauthorized
	}
	if nativeCtx.Err() != nil || automationCtx.Err() != nil || store == nil || authorize == nil || !binding.valid() || !nativeRevision(binding.NavigationID) || !nativeRevision(metadata.Revision) || !expires.After(time.Now()) || expires.After(time.Now().Add(5*time.Minute)) {
		return nil, ErrUnavailable
	}
	if deliveryCall(func() error { return authorize(automationCtx) }) != nil {
		return nil, ErrUnavailable
	}
	actual, e := store.Metadata(nativeCtx, binding.Target)
	if e != nil || actual != metadata || nativeCtx.Err() != nil || automationCtx.Err() != nil || !expires.After(time.Now()) {
		return nil, ErrUnavailable
	}
	if deliveryCall(func() error { return authorize(automationCtx) }) != nil {
		return nil, ErrUnavailable
	}
	return &DeliverySelection{state: &deliverySelectionState{store: store, namespace: actor.Namespace, clientID: actor.ClientID, consent: consent, binding: binding, metadata: metadata, expires: expires, authorize: authorize}}, nil
}

// Revoke is a trusted local cancellation operation. It never modifies the Vault,
// consent grants, delivery attempt ledger or existing exposure protection.
func (s *DeliverySelection) Revoke() {
	if s == nil || s.state == nil {
		return
	}
	s.state.mu.Lock()
	s.state.revoked = true
	s.state.mu.Unlock()
}

// Verify is a metadata-only guard for every private probe and credential write.
// It neither calls authorization hooks nor opens the Store, so it is safe inside
// ConsumeRevision's custody lock. The host must combine it with actual consent
// and delivery-exposure verification; it is not a substitute for those checks.
func (s *DeliverySelection) Verify(ctx context.Context, recipient DeliveryRecipient) error {
	if s == nil || s.state == nil {
		return ErrUnavailable
	}
	state := s.state
	actor, err := auth.FromContext(ctx)
	consent, ok := auth.ConsentBindingFromContext(ctx)
	if err != nil || actor.Validate() != nil || !actor.HasScope("desktop:control") || actor.Namespace != state.namespace || actor.ClientID != state.clientID || !ok || consent != state.consent {
		return auth.ErrUnauthorized
	}
	expected := DeliveryRecipient{state.binding.SessionID, state.binding.DocumentID, state.binding.NavigationID, state.binding.Target.Origin}
	if ctx.Err() != nil || recipient != expected {
		return ErrUnavailable
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.revoked || !time.Now().Before(state.expires) {
		return ErrUnavailable
	}
	return nil
}

// UseBinding admits a synchronous trusted host callback, never a JSON/MCP result.
// It preserves the selected revision; callback must use ConsumeRevision. A
// ciphertext change after this check is still refused at that final boundary.
// Selection reuse is allowed within the same exact consent/recipient; delivery
// attempts and exposure leases remain independently one-shot and durable.
func (s *DeliverySelection) UseBinding(ctx context.Context, recipient DeliveryRecipient, use func(Binding, Reference, string) error) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrUnavailable
		}
	}()
	if s == nil || s.state == nil || use == nil {
		return ErrUnavailable
	}
	state := s.state
	if err := s.Verify(ctx, recipient); err != nil {
		return err
	}
	state.mu.Lock()
	if state.revoked || state.busy || !time.Now().Before(state.expires) {
		state.mu.Unlock()
		return ErrUnavailable
	}
	state.busy = true
	state.mu.Unlock()
	defer func() { state.mu.Lock(); state.busy = false; state.mu.Unlock() }()
	valid := func() bool { return s.Verify(ctx, recipient) == nil }
	if !valid() || deliveryCall(func() error { return state.authorize(ctx) }) != nil {
		return ErrUnavailable
	}
	metadata, e := state.store.Metadata(ctx, state.binding.Target)
	if e != nil || metadata != state.metadata {
		return ErrUnavailable
	}
	if !valid() || deliveryCall(func() error { return state.authorize(ctx) }) != nil || !valid() {
		return ErrUnavailable
	}
	if deliveryCall(func() error { return use(state.binding, state.metadata.Reference, state.metadata.Revision) }) != nil || !valid() {
		return ErrUnavailable
	}
	return nil
}
