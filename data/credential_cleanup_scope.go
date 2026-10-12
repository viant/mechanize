package data

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/viant/mechanize/auth"
)

type credentialCleanupKey struct{}
type credentialCleanupAuthority struct {
	preparation   CredentialPreparationRecord
	attempts      map[string]CredentialDeliveryRecord
	guard         func(context.Context) error
	retiredBirth  string
	preflightOnly bool
	active        atomic.Bool
}

// WithCredentialCleanupAuthority is an internal recovery seam. The host must
// load complete original records through generated components and independently
// prove exact browser retirement under current reusable control consent. It
// grants no browser input, secret consumption, original-session impersonation,
// or resolution of unknown effects. Every close preserves dispatch knowledge.
// An empty complete child snapshot represents an unfilled preparation; it still
// requires the same independently proved browser retirement and CAS closure.
func WithCredentialCleanupAuthority(ctx context.Context, r CredentialPreparationRecord, attempts []CredentialDeliveryRecord, guard func(context.Context) error) (context.Context, func(), error) {
	return withCredentialCleanupAuthority(ctx, r, attempts, "", guard)
}

// WithCredentialPreflightCleanupAuthority cannot retire a delivery attempt.
// CloseCredentialPreparation must independently load the complete zero-child
// snapshot under the held user lock before its generated CAS may use this seal.
// Guard proves that no private input or admission remains pending in the broker.
func WithCredentialPreflightCleanupAuthority(ctx context.Context, r CredentialPreparationRecord, guard func(context.Context) error) (context.Context, func(), error) {
	sealed, stop, e := withCredentialCleanupAuthority(ctx, r, nil, "", guard)
	if e != nil {
		return nil, nil, e
	}
	sealed.Value(credentialCleanupKey{}).(*credentialCleanupAuthority).preflightOnly = true
	return sealed, stop, nil
}
func CredentialPreflightCleanupPreparation(ctx context.Context) (CredentialPreparationRecord, bool, error) {
	seal, ok := ctx.Value(credentialCleanupKey{}).(*credentialCleanupAuthority)
	if !ok || !seal.preflightOnly {
		return CredentialPreparationRecord{}, false, nil
	}
	actual := requireCredentialCleanup(ctx)
	if actual == nil {
		return CredentialPreparationRecord{}, true, ErrCredentialDeliveryAuthority
	}
	return actual.preparation, true, nil
}

// WithCredentialRetirementAuthority retires only exposure protection after the
// host independently proves the immutable normal-quit plan and original kernel
// process exit. Unknown dispatch knowledge remains unknown and cannot be replayed.
// Every child must belong to the same retired birth; the guard is rechecked at
// each generated CAS and cannot confer browser input or secret-read authority.
func WithCredentialRetirementAuthority(ctx context.Context, r CredentialPreparationRecord, attempts []CredentialDeliveryRecord, retiredBirth string, guard func(context.Context) error) (context.Context, func(), error) {
	if retiredBirth == "" {
		return nil, nil, ErrCredentialDeliveryAuthority
	}
	return withCredentialCleanupAuthority(ctx, r, attempts, retiredBirth, guard)
}

// WithCredentialSourceAbsenceAuthority is the exact-document counterpart of
// process retirement. Every retained attempt must be covered by an immutable
// source identity and the Host guard must independently prove all sources absent.
// It retires protection only; unknown dispatch knowledge remains unchanged.
func WithCredentialSourceAbsenceAuthority(ctx context.Context, r CredentialPreparationRecord, attempts []CredentialDeliveryRecord, sources []CredentialProtectionScopeRecord, guard func(context.Context) error) (context.Context, func(), error) {
	if len(sources) == 0 || len(sources) > 513 {
		return nil, nil, ErrCredentialDeliveryAuthority
	}
	birth := sources[0].ChromeStartToken
	for _, s := range sources {
		if s.Namespace != r.Namespace || s.ClientID != r.ClientID || s.PreparationID != r.PreparationID || s.Origin != r.Origin || s.ChromeStartToken == "" || s.ChromeStartToken != birth || s.ProfileChannel == "" || s.BrowserInstance == "" || s.TabID <= 0 || s.FrameID != 0 || s.DocumentID == "" || s.DocumentGeneration < 1 {
			return nil, nil, ErrCredentialDeliveryAuthority
		}
	}
	for _, a := range attempts {
		covered := false
		for _, s := range sources {
			covered = covered || a.ProfileChannel == s.ProfileChannel && a.BrowserInstance == s.BrowserInstance && a.TabID == s.TabID && a.DocumentID == s.DocumentID && a.ChromeStartToken == s.ChromeStartToken
		}
		if !covered {
			return nil, nil, ErrCredentialDeliveryAuthority
		}
	}
	return withCredentialCleanupAuthority(ctx, r, attempts, birth, guard)
}

func withCredentialCleanupAuthority(ctx context.Context, r CredentialPreparationRecord, attempts []CredentialDeliveryRecord, retiredBirth string, guard func(context.Context) error) (context.Context, func(), error) {
	p, e := auth.FromContext(ctx)
	c, ok := auth.ConsentBindingFromContext(ctx)
	if e != nil || p.Validate() != nil || !p.HasScope("desktop:control") || p.ClientID == "" || p.Namespace != r.Namespace || p.ClientID != r.ClientID || !ok || c.SessionID == "" || c.GrantID == "" || c.Purpose == "" || guard == nil || !credentialDeliveryGuard(ctx, guard) || r.ProtectionState != "held" || r.Revision != 1 || !deliveryHex.MatchString(r.PreparationID) || len(attempts) > 512 {
		return nil, nil, ErrCredentialDeliveryAuthority
	}
	if _, e = RequireScope(ctx, r.Namespace); e != nil {
		return nil, nil, ErrCredentialDeliveryAuthority
	}
	a := &credentialCleanupAuthority{preparation: r, attempts: make(map[string]CredentialDeliveryRecord), guard: guard, retiredBirth: retiredBirth}
	for _, v := range attempts {
		unknownRetired := retiredBirth != "" && v.ChromeStartToken == retiredBirth && v.DispatchState == "unknown"
		if v.Namespace != r.Namespace || v.ClientID != r.ClientID || v.SessionID != r.SessionID || v.SelectionID != r.PreparationID || v.GrantID != r.GrantID || v.PurposeHash != r.PurposeHash || v.SelectedRevision != r.SelectedRevision || v.Origin != r.Origin || !deliveryHex.MatchString(v.AttemptID) || a.attempts[v.AttemptID].AttemptID != "" || (v.DispatchState != "dispatched" && v.DispatchState != "notDispatched" && !unknownRetired) || (v.ProtectionState != "held" && v.ProtectionState != "closed" && !(unknownRetired && v.ProtectionState == "retired")) || (v.Revision < 2 && !(unknownRetired && v.Revision == 1)) || retiredBirth != "" && v.ChromeStartToken != retiredBirth {
			return nil, nil, ErrCredentialDeliveryAuthority
		}
		a.attempts[v.AttemptID] = v
	}
	a.active.Store(true)
	return context.WithValue(ctx, credentialCleanupKey{}, a), func() { a.active.Store(false) }, nil
}
func requireCredentialCleanup(ctx context.Context) *credentialCleanupAuthority {
	a, ok := ctx.Value(credentialCleanupKey{}).(*credentialCleanupAuthority)
	if !ok || !a.active.Load() || !credentialDeliveryGuard(ctx, a.guard) {
		return nil
	}
	p, e := auth.FromContext(ctx)
	if e != nil || !p.HasScope("desktop:control") || p.Namespace != a.preparation.Namespace || p.ClientID != a.preparation.ClientID {
		return nil
	}
	return a
}
func cleanupPreparationAllowed(ctx context.Context, r CredentialPreparationRecord) bool {
	a := requireCredentialCleanup(ctx)
	if a == nil {
		return false
	}
	if r == a.preparation {
		return true
	}
	expected := a.preparation
	expected.ProtectionState = "closed"
	expected.Revision++
	return r == expected
}
func cleanupDeliveryAllowed(ctx context.Context, value CredentialDeliveryAuthority) bool {
	a := requireCredentialCleanup(ctx)
	if a == nil {
		return false
	}
	old, ok := a.attempts[value.Record.AttemptID]
	if !ok {
		return false
	}
	if value.Before == nil {
		return value.Record == old
	}
	protection := "closed"
	if old.DispatchState == "unknown" && a.retiredBirth != "" && old.ChromeStartToken == a.retiredBirth {
		protection = "retired"
	}
	if *value.Before != old || old.ProtectionState != "held" || value.Record.ProtectionState != protection || value.Record.Revision != old.Revision+1 {
		return false
	}
	next := value.Record
	next.ProtectionState = old.ProtectionState
	next.Revision = old.Revision
	next.UpdatedAt = old.UpdatedAt
	t, e := time.Parse(time.RFC3339Nano, value.Record.UpdatedAt)
	before, be := time.Parse(time.RFC3339Nano, old.UpdatedAt)
	return next == old && e == nil && be == nil && !t.Before(before) && !t.After(time.Now().Add(time.Minute))
}

// ValidateCredentialPreparationClose compares both CAS snapshots to the sealed
// original. SQLite separately refuses closure while any child is held or has an unretired unknown outcome.
func ValidateCredentialPreparationClose(ctx context.Context, row, previous any) error {
	a := requireCredentialCleanup(ctx)
	if a == nil {
		return ErrCredentialDeliveryAuthority
	}
	expected := a.preparation
	expected.ProtectionState = "closed"
	expected.Revision++
	decode := func(v any) (CredentialPreparationRecord, error) {
		raw, e := json.Marshal(v)
		if e != nil {
			return CredentialPreparationRecord{}, e
		}
		var r CredentialPreparationRecord
		e = json.Unmarshal(raw, &r)
		return r, e
	}
	actual, e := decode(row)
	old, oe := decode(previous)
	if e != nil || oe != nil || actual != expected || old != a.preparation {
		return ErrCredentialDeliveryAuthority
	}
	return nil
}
