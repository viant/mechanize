package vault

import (
	"bytes"
	"context"
	"fmt"
	"github.com/viant/mechanize/auth"
	"io"
	"sync"
	"time"
	"unicode/utf8"
)

// RecordDelivery is a consent-authorized, revision-bound private capability. It has
// no value getter. The automation actor never acquires NativeHuman authority.
// A trusted host may bind subsequent privately verified documents at the same
// exact origin/session while this short-lived capability remains valid.
type RecordDelivery struct{ state *recordDeliveryState }
type recordDeliveryState struct {
	mu       sync.Mutex
	store    *RecordStore
	actor    auth.Principal
	consent  auth.ConsentBinding
	target   Target
	metadata RecordMetadata
	expires  time.Time
	revoked  bool
}

func (RecordDelivery) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }
func (RecordDelivery) String() string               { return "[private record delivery withheld]" }
func (RecordDelivery) GoString() string             { return "[private record delivery withheld]" }
func (RecordDelivery) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private record delivery withheld]")
}

// ApproveRecordDelivery is available only to the authenticated native console.
// Standard credential fields are selected locally; neither the record key nor
// any field bytes leave custody. Arbitrary records cannot become plaintext APIs.
func ApproveRecordDelivery(nativeCtx, automationCtx context.Context, store *RecordStore, target Target, metadata RecordMetadata, expires time.Time) (*RecordDelivery, error) {
	n, ne := auth.FromContext(nativeCtx)
	p, pe := auth.FromContext(automationCtx)
	c, ok := auth.ConsentBindingFromContext(automationCtx)
	if ne != nil || pe != nil || n.Validate() != nil || p.Validate() != nil || !auth.NativeHuman(nativeCtx) || auth.NativeHuman(automationCtx) || !n.HasScope("consent:admin") || n.Namespace != p.Namespace || p.ClientID == "" || !p.HasScope("desktop:control") || !ok || c.SessionID == "" || c.GrantID == "" || c.Purpose == "" {
		return nil, auth.ErrUnauthorized
	}
	if store == nil || target.Validate() != nil || !nativeRevision(metadata.Reference.ID) || !nativeRevision(metadata.Revision) || !expires.After(time.Now()) || expires.After(time.Now().Add(5*time.Minute)) {
		return nil, ErrUnavailable
	}
	d := &RecordDelivery{state: &recordDeliveryState{store: store, actor: p, consent: c, target: target, metadata: metadata, expires: expires}}
	err := store.store.writeLock(nativeCtx, func() error {
		actual, plain, e := store.load(nativeCtx, p.Namespace, metadata.Reference.ID)
		defer clear(plain)
		if e != nil || actual != metadata {
			return ErrUnavailable
		}
		_, e = recordCredentials(plain)
		return e
	})
	if err != nil || nativeCtx.Err() != nil || automationCtx.Err() != nil {
		return nil, ErrUnavailable
	}
	return d, nil
}
func recordCredentials(plain []byte) (Credentials, error) {
	_, fields, e := parseRecord(plain)
	if e != nil {
		return Credentials{}, ErrUnavailable
	}
	kind, typed, err := scyRecordType(fields)
	if err != nil {
		return Credentials{}, ErrUnavailable
	}
	if typed {
		if kind != "basic" {
			return Credentials{}, ErrUnavailable
		}
		credentials, e := scyBasicCredentials(fields)
		if e != nil {
			return Credentials{}, ErrUnavailable
		}
		return credentials, nil
	}
	c := Credentials{}
	for _, f := range fields {
		if bytes.Equal(f[0], []byte("username")) {
			c.username = f[1]
		}
		if bytes.Equal(f[0], []byte("password")) {
			c.password = f[1]
		}
	}
	if len(c.username) == 0 || len(c.password) == 0 || len(c.username)+len(c.password) > maxCredentialBytes || !utf8.Valid(c.username) || !utf8.Valid(c.password) || bytes.ContainsRune(c.username, 0) || bytes.ContainsRune(c.password, 0) {
		return Credentials{}, ErrUnavailable
	}
	return c, nil
}
func (d *RecordDelivery) Revoke() {
	if d != nil && d.state != nil {
		d.state.mu.Lock()
		d.state.revoked = true
		d.state.mu.Unlock()
	}
}
func (d *RecordDelivery) Verify(ctx context.Context, b Binding) error { return d.verify(ctx, b, false) }

// VerifyPrivacyBinding verifies retained approval provenance for metadata-only
// privacy qualification after a known submit. It cannot renew secret use:
// ConsumeRevision and UseBinding always call expiry-enforcing Verify. Revocation,
// ownership, exact consent/target and current-context checks remain mandatory.
func (d *RecordDelivery) VerifyPrivacyBinding(ctx context.Context, b Binding) error {
	return d.verify(ctx, b, true)
}
func (d *RecordDelivery) verify(ctx context.Context, b Binding, privacyOnly bool) error {
	if d == nil || d.state == nil {
		return ErrUnavailable
	}
	p, e := auth.FromContext(ctx)
	c, ok := auth.ConsentBindingFromContext(ctx)
	if e != nil || !ok || p.Namespace != d.state.actor.Namespace || p.ClientID != d.state.actor.ClientID || !p.HasScope("desktop:control") || c != d.state.consent {
		return auth.ErrUnauthorized
	}
	d.state.mu.Lock()
	defer d.state.mu.Unlock()
	if ctx.Err() != nil || d.state.revoked || !privacyOnly && !time.Now().Before(d.state.expires) || !b.valid() || !nativeRevision(b.NavigationID) || b.SessionID != d.state.consent.SessionID || b.Target != d.state.target {
		return ErrUnavailable
	}
	return nil
}

// NewRecordDeliveryManager consumes only the approved record revision. Fresh is
// the host's actual private renderer/consent/exposure guard, never a JSON claim.
// It does not enroll legacy resolution, Ensure, Submit, or a mutable lookup.
func NewRecordDeliveryManager(d *RecordDelivery, fresh func(context.Context, Binding) (Binding, error)) (*Manager, error) {
	if d == nil || d.state == nil || fresh == nil {
		return nil, ErrUnavailable
	}
	return &Manager{hooks: Hooks{Fresh: fresh}, privateConsume: func(ctx context.Context, b Binding, ref Reference, revision string, use func(Credentials) error) error {
		if use == nil || ref.ResourceURL != "private-record:"+d.state.metadata.Reference.ID || revision != d.state.metadata.Revision || d.Verify(ctx, b) != nil {
			return ErrUnavailable
		}
		return d.state.store.store.writeLock(ctx, func() error {
			if d.Verify(ctx, b) != nil {
				return ErrUnavailable
			}
			actual, plain, e := d.state.store.load(ctx, d.state.actor.Namespace, d.state.metadata.Reference.ID)
			defer clear(plain)
			if e != nil || actual != d.state.metadata {
				return ErrUnavailable
			}
			c, e := recordCredentials(plain)
			if e != nil {
				return ErrUnavailable
			}
			if d.Verify(ctx, b) != nil {
				return ErrUnavailable
			}
			return deliveryCall(func() error { return use(c) })
		})
	}}, nil
}

// UseBinding exposes routing metadata only to the synchronous private host.
func (d *RecordDelivery) UseBinding(ctx context.Context, b Binding, use func(Reference, string) error) error {
	if use == nil || d.Verify(ctx, b) != nil {
		return ErrUnavailable
	}
	return deliveryCall(func() error {
		return use(Reference{ResourceURL: "private-record:" + d.state.metadata.Reference.ID}, d.state.metadata.Revision)
	})
}
