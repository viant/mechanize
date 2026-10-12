package host

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
)

// ConsentBroker composes private generated components; its immutable service
// instances never share connector namespaces. No caller can select storage.
type ConsentBroker struct {
	options      ConsentBrokerOptions
	mu           sync.Mutex
	services     map[string]*consent.Service
	clients      map[string]auth.Principal
	policyLane   chan struct{}
	policyGrants map[string]*consent.Grant
}
type ConsentBrokerOptions struct {
	ControllerPolicy     func(context.Context, auth.Principal) (context.Context, time.Time, func(), error)
	Invoke               func(context.Context, auth.Principal, exec.ComponentRequest) (any, error)
	Enrolled             func(context.Context, auth.Principal) (User, error)
	SessionOwned         func(context.Context, auth.Principal, string) error
	Policy               func(context.Context, auth.Principal, consent.Scope, []consent.Mode, int) error
	RecoverCleanup       func(context.Context, auth.Principal, consent.Scope) error
	WithCleanupProof     func(context.Context, auth.Principal, consent.Scope, func(context.Context) error) error
	RecoverNativeCleanup func(context.Context, auth.Principal, consent.Scope) error
}

func NewConsentBroker(o ConsentBrokerOptions) (*ConsentBroker, error) {
	if o.Invoke == nil || o.Enrolled == nil || o.SessionOwned == nil || o.Policy == nil {
		return nil, errors.New("complete consent identity, policy and private Datly bindings required")
	}
	return &ConsentBroker{options: o, services: map[string]*consent.Service{}, clients: map[string]auth.Principal{}, policyLane: make(chan struct{}, 1), policyGrants: map[string]*consent.Grant{}}, nil
}
func (b *ConsentBroker) bound(ctx context.Context, p auth.Principal) (context.Context, *consent.Service, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.Namespace != p.Namespace {
		return nil, nil, auth.ErrUnauthorized
	}
	if _, err = b.options.Enrolled(ctx, actual); err != nil {
		return nil, nil, err
	}
	scope := data.Scope{Namespace: actual.Namespace}
	if trusted, present := data.CurrentScope(ctx); present {
		if trusted.Namespace != actual.Namespace {
			return nil, nil, auth.ErrUnauthorized
		}
		// Preserve host-admitted renderer/desktop authority across consent calls.
		// This comes only from the private invocation context, never tool fields.
		scope = trusted
	}
	ctx, err = data.WithScope(ctx, scope)
	if err != nil {
		return nil, nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if s := b.services[actual.Namespace]; s != nil {
		return ctx, s, nil
	}
	namespace := actual.Namespace
	var recoverNative func(context.Context, consent.Client, consent.Scope) error
	if b.options.RecoverNativeCleanup != nil {
		recoverNative = func(ctx context.Context, c consent.Client, scope consent.Scope) error {
			p, err := auth.FromContext(ctx)
			if err != nil || p.Namespace != namespace || p.ClientID != c.ID {
				return consent.ErrCleanupUnconfirmed
			}
			return b.options.RecoverNativeCleanup(ctx, p, scope)
		}
	}
	var withProof func(context.Context, consent.Client, consent.Scope, func(context.Context) error) error
	if b.options.WithCleanupProof != nil {
		withProof = func(ctx context.Context, c consent.Client, scope consent.Scope, commit func(context.Context) error) error {
			p, err := auth.FromContext(ctx)
			if err != nil || p.Namespace != namespace || p.ClientID != c.ID {
				return consent.ErrCleanupUnconfirmed
			}
			return b.options.WithCleanupProof(ctx, p, scope, commit)
		}
	}
	s, err := consent.New(consent.Options{Namespace: namespace,
		WithCleanupProof: withProof,
		RecoverCleanup: func(ctx context.Context, c consent.Client, scope consent.Scope) error {
			p, err := auth.FromContext(ctx)
			if err != nil || p.Namespace != namespace || p.ClientID != c.ID || b.options.RecoverCleanup == nil {
				return consent.ErrCleanupUnconfirmed
			}
			return b.options.RecoverCleanup(ctx, p, scope)
		},
		RecoverNativeCleanup: recoverNative,
		Invoke: func(ctx context.Context, req exec.ComponentRequest) (any, error) {
			p, e := auth.FromContext(ctx)
			if e != nil || p.Namespace != namespace {
				return nil, auth.ErrUnauthorized
			}
			return b.options.Invoke(ctx, p, req)
		},
		VerifyClient: func(ctx context.Context) (consent.Client, error) { return b.client(ctx, namespace) },
		VerifyPolicy: func(ctx context.Context, c consent.Client) error {
			p, e := auth.FromContext(ctx)
			if e != nil || p.ClientID != c.ID || b.options.ControllerPolicy == nil {
				return auth.ErrUnauthorized
			}
			_, _, release, e := b.options.ControllerPolicy(ctx, p)
			if release != nil {
				release()
			}
			return e
		},
		VerifyActor: func(ctx context.Context) (consent.Actor, error) {
			p, e := auth.FromContext(ctx)
			if e != nil || p.Namespace != namespace || !auth.NativeHuman(ctx) {
				return consent.Actor{}, auth.ErrUnauthorized
			}
			return consent.Actor{ID: p.Subject, Human: true, Admin: true}, nil
		},
		ResolveClient: func(ctx context.Context, id, session string) (consent.Client, error) {
			b.mu.Lock()
			p, ok := b.clients[namespace+":"+id+":"+session]
			b.mu.Unlock()
			if !ok || b.options.SessionOwned(auth.WithPrincipal(ctx, p), p, session) != nil {
				return consent.Client{}, auth.ErrUnauthorized
			}
			return consent.Client{ID: id, DisplayName: p.ClientName, SessionID: session, Verification: "verified"}, nil
		},
		Policy: func(ctx context.Context, c consent.Client, scope consent.Scope, modes []consent.Mode, duration int) error {
			b.mu.Lock()
			p, ok := b.clients[namespace+":"+c.ID+":"+c.SessionID]
			b.mu.Unlock()
			if !ok {
				return auth.ErrUnauthorized
			}
			return b.options.Policy(auth.WithPrincipal(ctx, p), p, scope, modes, duration)
		},
	})
	if err != nil {
		return nil, nil, err
	}
	b.services[namespace] = s
	return ctx, s, nil
}
func (b *ConsentBroker) client(ctx context.Context, namespace string) (consent.Client, error) {
	p, e := auth.FromContext(ctx)
	binding, ok := ConsentBindingFromContext(ctx)
	if e != nil || p.Namespace != namespace || p.ClientID == "" || p.ClientName == "" || !ok || b.options.SessionOwned(ctx, p, binding.SessionID) != nil {
		return consent.Client{}, auth.ErrUnauthorized
	}
	b.mu.Lock()
	b.clients[namespace+":"+p.ClientID+":"+binding.SessionID] = p
	b.mu.Unlock()
	return consent.Client{ID: p.ClientID, DisplayName: p.ClientName, SessionID: binding.SessionID, Verification: "verified"}, nil
}
func (b *ConsentBroker) Request(ctx context.Context, p auth.Principal, session string, in consent.RequestInput) (consent.Request, error) {
	ctx = WithConsentBinding(ctx, ConsentBinding{SessionID: session})
	ctx, s, e := b.bound(ctx, p)
	if e != nil {
		return consent.Request{}, e
	}
	return s.CreateRequest(ctx, session, in)
}
func (b *ConsentBroker) Authorize(ctx context.Context, p auth.Principal, op consent.Operation) (*consent.Lease, error) {
	bound, releasePolicy, err := b.controllerPolicyContext(ctx, p)
	if err != nil {
		return nil, err
	}
	retained := false
	defer func() {
		if !retained && releasePolicy != nil {
			releasePolicy()
		}
	}()
	ctx = bound
	binding, ok := ConsentBindingFromContext(ctx)
	if !ok || op.SessionID != binding.SessionID || op.GrantID != binding.GrantID || op.Purpose != binding.Purpose {
		return nil, auth.ErrUnauthorized
	}
	ctx, s, e := b.bound(ctx, p)
	if e != nil {
		return nil, e
	}
	lease, err := s.Authorize(ctx, op)
	if err != nil {
		return nil, err
	}
	previous := lease.Release
	lease.Release = func() { defer releasePolicy(); previous() }
	retained = true
	return lease, nil
}

// FindPermanentGrant only searches grants owned by the current verified client.
// It cannot create or extend trust; the signed human console owns that decision.
func (b *ConsentBroker) FindPermanentGrant(ctx context.Context, p auth.Principal, op consent.Operation) (*consent.Grant, error) {
	ctx, service, err := b.bound(ctx, p)
	if err != nil {
		return nil, err
	}
	return service.FindPermanentGrant(ctx, op)
}

func (b *ConsentBroker) authorizeCleanupQuit(ctx context.Context, p auth.Principal) (*consent.Lease, error) {
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if !ok || binding.Purpose == "" {
		return nil, auth.ErrUnauthorized
	}
	ctx, service, err := b.bound(ctx, p)
	if err != nil {
		return nil, err
	}
	lease, grantID, err := service.AuthorizeCleanupQuit(ctx, consent.Operation{GrantID: binding.GrantID, SessionID: binding.SessionID, Purpose: binding.Purpose, Scope: consent.Scope{Kind: "application", BundleID: "com.google.Chrome"}, Mode: consent.Control})
	if err != nil {
		return nil, err
	}
	binding.GrantID = grantID
	lease.Context = auth.WithConsentBinding(lease.Context, binding)
	return lease, nil
}

// NativeRPC is reachable only through the signed local console transport.
func (b *ConsentBroker) NativeRPC(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	p, e := auth.FromContext(ctx)
	if e != nil || !auth.NativeHuman(ctx) {
		return nil, auth.ErrUnauthorized
	}
	ctx, s, e := b.bound(ctx, p)
	if e != nil {
		return nil, e
	}
	switch method {
	case "snapshot":
		return s.Snapshot(ctx)
	case "decide":
		var in struct {
			RequestID string           `json:"requestID"`
			Decision  consent.Decision `json:"decision"`
		}
		if e = json.Unmarshal(raw, &in); e != nil {
			return nil, e
		}
		return s.Decide(ctx, in.RequestID, in.Decision)
	case "revoke":
		var in struct {
			GrantID string `json:"grantID"`
		}
		if e = json.Unmarshal(raw, &in); e != nil {
			return nil, e
		}
		state, e := s.Revoke(ctx, in.GrantID)
		return map[string]any{"status": state}, e
	default:
		return nil, errors.New("unsupported native consent method")
	}
}

// GetSnapshot is the native console's authenticated reconciliation read.
func (b *ConsentBroker) GetSnapshot(ctx context.Context, p auth.Principal) (consent.Snapshot, error) {
	if !auth.NativeHuman(ctx) {
		return consent.Snapshot{}, auth.ErrUnauthorized
	}
	ctx, s, e := b.bound(ctx, p)
	if e != nil {
		return consent.Snapshot{}, e
	}
	return s.Snapshot(ctx)
}

func (b *ConsentBroker) RequestStatus(ctx context.Context, p auth.Principal, sessionID, requestID string) (consent.RequestStatus, error) {
	ctx = WithConsentBinding(ctx, ConsentBinding{SessionID: sessionID})
	ctx, s, err := b.bound(ctx, p)
	if err != nil {
		return consent.RequestStatus{}, err
	}
	return s.RequestStatus(ctx, requestID)
}
