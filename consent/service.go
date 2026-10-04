package consent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/data"
	"github.com/viant/xdatly/handler"
	"sort"
	"sync"
	"time"
)

type Service struct {
	options  Options
	mu       sync.Mutex
	active   map[string]map[string]context.CancelFunc
	blocked  map[string]bool
	known    map[string]bool
	bindings map[string]map[string]Client
}

func New(options Options) (*Service, error) {
	if _, err := data.WithScope(context.Background(), data.Scope{Namespace: options.Namespace}); err != nil {
		return nil, err
	}
	if options.Invoke == nil || options.VerifyClient == nil || options.VerifyActor == nil || options.ResolveClient == nil || options.Policy == nil {
		return nil, fmt.Errorf("authenticated broker callbacks required")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.RequestTTL == 0 {
		options.RequestTTL = 2 * time.Minute
	}
	if options.MaxDuration == 0 {
		options.MaxDuration = 15 * time.Minute
	}
	if options.RequestTTL < time.Second || options.RequestTTL > 5*time.Minute || options.MaxDuration < time.Second || options.MaxDuration > time.Hour {
		return nil, fmt.Errorf("invalid broker duration ceiling")
	}
	return &Service{options: options, active: map[string]map[string]context.CancelFunc{}, blocked: map[string]bool{}, known: map[string]bool{}, bindings: map[string]map[string]Client{}}, nil
}
func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func (s *Service) client(ctx context.Context) (Client, error) {
	c, err := s.options.VerifyClient(ctx)
	if err != nil {
		return Client{}, err
	}
	if c.ID == "" || c.DisplayName == "" || c.SessionID == "" || c.Verification != "verified" {
		return Client{}, fmt.Errorf("broker verified client and session required")
	}
	return c, nil
}
func (s *Service) actor(ctx context.Context) (Actor, error) {
	a, err := s.options.VerifyActor(ctx)
	if err != nil {
		return Actor{}, err
	}
	if a.ID == "" || !a.Human || !a.Admin {
		return Actor{}, fmt.Errorf("separately authenticated human consent administrator required")
	}
	return a, nil
}
func (s *Service) namespace(ctx context.Context) (string, error) { // no caller-selected storage
	c, ok := data.CurrentScope(ctx)
	if !ok || c.Namespace != s.options.Namespace {
		return "", fmt.Errorf("consent service connector scope mismatch")
	}
	return c.Namespace, nil
}
func (s *Service) resolve(ctx context.Context, r record) (Client, error) {
	c, err := s.options.ResolveClient(ctx, r.ClientID, r.SessionID)
	if err != nil {
		return Client{}, err
	}
	if c.ID != r.ClientID || c.SessionID != r.SessionID || c.Verification != "verified" {
		return Client{}, fmt.Errorf("consent client session no longer authenticated")
	}
	return c, nil
}
func (s *Service) policy(ctx context.Context, c Client, r record) error {
	scope, modes, err := r.details()
	if err != nil {
		return err
	}
	if err := validateInput(RequestInput{Scope: scope, Modes: modes, Purpose: r.Purpose, DurationSeconds: r.DurationSeconds}, s.options.MaxDuration); err != nil {
		return err
	}
	return s.options.Policy(ctx, c, scope, modes, r.DurationSeconds)
}
func (s *Service) CreateRequest(ctx context.Context, sessionID string, in RequestInput) (Request, error) {
	c, err := s.client(ctx)
	if err != nil {
		return Request{}, err
	}
	if sessionID != c.SessionID {
		return Request{}, fmt.Errorf("authenticated session mismatch")
	}
	if err = validateInput(in, s.options.MaxDuration); err != nil {
		return Request{}, err
	}
	if err = s.options.Policy(ctx, c, in.Scope, in.Modes, in.DurationSeconds); err != nil {
		return Request{}, err
	}
	ns, err := s.namespace(ctx)
	if err != nil {
		return Request{}, err
	}
	id, err := randomID()
	if err != nil {
		return Request{}, err
	}
	grantID, err := randomID()
	if err != nil {
		return Request{}, err
	}
	scope, _ := json.Marshal(in.Scope)
	modes := append([]Mode(nil), in.Modes...)
	sort.Slice(modes, func(i, j int) bool { return modes[i] < modes[j] })
	modesJSON, _ := json.Marshal(modes)
	now := s.options.Now().UTC()
	r := record{Namespace: ns, ID: id, ClientID: c.ID, ClientName: c.DisplayName, SessionID: c.SessionID, ScopeJSON: string(scope), ModesJSON: string(modesJSON), Purpose: in.Purpose, DurationSeconds: in.DurationSeconds, CreatedAt: int(now.UnixMilli()), RequestExpiresAt: int(now.Add(s.options.RequestTTL).UnixMilli()), RequestState: "pending", GrantID: grantID, GrantState: "none", Revision: 1}
	if err = s.write(ctx, "create", c.ID, r, nil); err != nil {
		return Request{}, err
	}
	return r.request()
}
func (s *Service) ListRequests(ctx context.Context) ([]Request, error) {
	a, err := s.actor(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.read(ctx, "consentrequests", "*", a.ID)
	if err != nil {
		return nil, err
	}
	result := []Request{}
	now := int(s.options.Now().UnixMilli())
	for _, r := range rows {
		if r.RequestState != "pending" || r.RequestExpiresAt <= now {
			continue
		}
		if _, err = s.resolve(ctx, r); err != nil {
			continue
		}
		request, err := r.request()
		if err != nil {
			return nil, err
		}
		result = append(result, request)
	}
	return result, nil
}
func (s *Service) ListGrants(ctx context.Context) ([]Grant, error) {
	a, err := s.actor(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.read(ctx, "consentgrants", "*", a.ID)
	if err != nil {
		return nil, err
	}
	out := []Grant{}
	for _, r := range rows {
		if r.Decision == "" || r.Decision == string(Deny) {
			continue
		}
		g, err := r.grant(s.options.Now())
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}
func (s *Service) Snapshot(ctx context.Context) (Snapshot, error) {
	requests, err := s.ListRequests(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	grants, err := s.ListGrants(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	// Snapshot doubles as the broker's bounded reconciliation poll. Unknown
	// cleanup remains unknown until the helper provides authoritative evidence.
	changed := false
	for _, grant := range grants {
		if grant.RevocationState == Requested || grant.RevocationState == Stopping {
			if _, err = s.Revoke(ctx, grant.ID); err != nil {
				return Snapshot{}, err
			}
			changed = true
		}
	}
	if changed {
		grants, err = s.ListGrants(ctx)
	}
	return Snapshot{Requests: requests, Grants: grants}, err
}
func (s *Service) lookup(ctx context.Context, id, actor string) (record, error) {
	rows, err := s.read(ctx, "consentrequests", id, actor)
	if err != nil {
		return record{}, err
	}
	for _, r := range rows {
		if r.ID == id || r.GrantID == id {
			return r, nil
		}
	}
	return record{}, fmt.Errorf("authorized consent not found")
}
func (s *Service) Decide(ctx context.Context, requestID string, decision Decision) (*Grant, error) {
	a, err := s.actor(ctx)
	if err != nil {
		return nil, err
	}
	if decision != AllowOnce && decision != AllowSession && decision != AllowUntilRevoked && decision != Deny {
		return nil, fmt.Errorf("invalid consent decision")
	}
	r, err := s.lookup(ctx, requestID, a.ID)
	if err != nil {
		return nil, err
	}
	if r.ID != requestID {
		return nil, fmt.Errorf("request identity required")
	}
	now := int(s.options.Now().UnixMilli())
	if r.RequestState != "pending" || r.RequestExpiresAt <= now {
		return nil, fmt.Errorf("expired or decided consent request")
	}
	previous := r
	c, err := s.resolve(ctx, r)
	if err != nil {
		return nil, err
	}
	if decision != Deny {
		if err = s.policy(ctx, c, r); err != nil {
			return nil, err
		}
	}
	r.RequestState = "decided"
	r.Decision = string(decision)
	r.Revision++
	if decision != Deny {
		r.GrantState = "active"
		r.GrantCreatedAt = now
		r.GrantExpiresAt = now + r.DurationSeconds*1000
		if decision == AllowUntilRevoked {
			r.GrantExpiresAt = 0
		}
	}
	if err = s.write(ctx, "decide", a.ID, r, &previous); err != nil {
		return nil, err
	}
	if decision == Deny {
		return nil, nil
	}
	s.mu.Lock()
	s.known[r.Namespace+":"+r.GrantID] = true
	s.mu.Unlock()
	g, err := r.grant(s.options.Now())
	return &g, err
}

// FindPermanentGrant returns a current matching approval for the verified client's
// owned session. Discovery never creates approval and Authorize rechecks authority
// immediately before dispatch. The generated reader remains the persistence boundary.
func (s *Service) FindPermanentGrant(ctx context.Context, op Operation) (*Grant, error) {
	c, err := s.client(ctx)
	if err != nil {
		return nil, err
	}
	if op.SessionID != c.SessionID {
		return nil, fmt.Errorf("operation session mismatch")
	}
	ns, err := s.namespace(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.read(ctx, "consenttrusted", "*", c.ID)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.Namespace != ns || r.ClientID != c.ID || !r.permanent() || r.GrantState != "active" || r.RevocationState != "" {
			continue
		}
		s.mu.Lock()
		blocked := s.blocked[ns+":"+r.GrantID]
		s.mu.Unlock()
		if blocked {
			continue
		}
		scope, modes, err := r.details()
		if err != nil {
			return nil, err
		}
		if !scope.Covers(op.Scope) {
			continue
		}
		matched := false
		for _, mode := range modes {
			if mode == op.Mode {
				matched = true
			}
		}
		if !matched {
			continue
		}
		if err = s.policy(ctx, c, r); err != nil {
			continue
		}
		if err = s.options.Policy(ctx, c, op.Scope, []Mode{op.Mode}, r.DurationSeconds); err != nil {
			continue
		}
		g, err := r.grant(s.options.Now())
		return &g, err
	}
	return nil, nil
}

func (s *Service) Authorize(ctx context.Context, op Operation) (*Lease, error) {
	c, err := s.client(ctx)
	if err != nil {
		return nil, err
	}
	if op.SessionID != c.SessionID {
		return nil, fmt.Errorf("operation session mismatch")
	}
	ns, err := s.namespace(ctx)
	if err != nil {
		return nil, err
	}
	key := ns + ":" + op.GrantID
	s.mu.Lock()
	blocked := s.blocked[key]
	s.mu.Unlock()
	if blocked {
		return nil, fmt.Errorf("active bound consent required")
	}
	r, err := s.lookup(ctx, op.GrantID, c.ID)
	if err != nil {
		return nil, err
	}
	if r.Namespace != ns || r.GrantID != op.GrantID || r.ClientID != c.ID || (!r.permanent() && r.SessionID != c.SessionID) || r.GrantState != "active" || r.RevocationState != "" || (!r.permanent() && r.GrantExpiresAt <= int(s.options.Now().UnixMilli())) {
		return nil, fmt.Errorf("active bound consent required")
	}
	scope, modes, err := r.details()
	if err != nil {
		return nil, err
	}
	if !scope.Covers(op.Scope) || (!r.permanent() && r.Purpose != op.Purpose) {
		return nil, fmt.Errorf("operation target exceeds consent scope or purpose differs")
	}
	found := false
	for _, m := range modes {
		if m == op.Mode {
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("operation mode exceeds consent")
	}
	if err = s.policy(ctx, c, r); err != nil {
		return nil, err
	}
	// A desktop approval does not bypass current policy for this resolved target
	// or mode. Check before consuming allow-once or admitting dispatch.
	if err = s.options.Policy(ctx, c, op.Scope, []Mode{op.Mode}, r.DurationSeconds); err != nil {
		return nil, err
	}
	if r.Decision == string(AllowOnce) {
		previous := r
		r.GrantState = "consumed"
		r.Revision++
		if err = s.write(ctx, "consume", c.ID, r, &previous); err != nil {
			return nil, err
		}
	} else if r.Decision != string(AllowSession) && !r.permanent() {
		return nil, fmt.Errorf("unsupported grant decision")
	}
	token, err := randomID()
	if err != nil {
		return nil, err
	}
	var leaseCtx context.Context
	var cancel context.CancelFunc
	if r.permanent() {
		leaseCtx, cancel = context.WithCancel(ctx)
	} else {
		leaseCtx, cancel = context.WithDeadline(ctx, time.UnixMilli(int64(r.GrantExpiresAt)))
	}
	// The generated once-consume CAS is authoritative. Registry admission is
	// separately atomic with inhibition so no dispatch can slip past a revoke
	// that began while its database lookup/consume was in progress.
	s.mu.Lock()
	if s.blocked[key] || (!r.permanent() && r.GrantExpiresAt <= int(s.options.Now().UnixMilli())) || ctx.Err() != nil {
		s.mu.Unlock()
		cancel()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("consent inhibited before dispatch admission")
	}
	if s.active[key] == nil {
		s.active[key] = map[string]context.CancelFunc{}
	}
	s.active[key][token] = cancel
	if s.bindings[key] == nil {
		s.bindings[key] = map[string]Client{}
	}
	s.bindings[key][token] = c
	s.mu.Unlock()
	var once sync.Once
	release := func() {
		once.Do(func() {
			cancel()
			s.mu.Lock()
			defer s.mu.Unlock()
			delete(s.active[key], token)
			delete(s.bindings[key], token)
			if len(s.active[key]) == 0 {
				delete(s.active, key)
				delete(s.bindings, key)
			}
		})
	}
	return &Lease{Context: leaseCtx, Release: release}, nil
}

// Revoke inhibits and cancels admitted input before waiting for generated
// persistence. It reports revoked only after durable transitions confirm that
// every registered dispatch has released following stop and cleanup.
func (s *Service) Revoke(ctx context.Context, grantID string) (RevocationState, error) {
	a, err := s.actor(ctx)
	if err != nil {
		return "", err
	}
	ns, err := s.namespace(ctx)
	if err != nil {
		return "", err
	}
	key := ns + ":" + grantID
	// A verified namespace administrator can inhibit before a generated lookup
	// waits on the execution admission lock. Never hold registrymu across I/O.
	s.inhibit(key)
	r, err := s.lookup(ctx, grantID, a.ID)
	if err != nil {
		return "", err
	}
	if r.GrantID != grantID || r.Decision == "" || r.Decision == string(Deny) {
		return "", fmt.Errorf("grant identity required")
	}

	if r.RevocationState == string(Revoked) {
		return Revoked, nil
	}
	advance := func(next RevocationState) error {
		previous := r
		r.RevocationState = string(next)
		if next == Revoked {
			r.GrantState = "revoked"
		}
		r.Revision++
		return s.write(ctx, "revoke", a.ID, r, &previous)
	}
	if r.RevocationState == "" {
		if err = advance(Requested); err != nil {
			return Requested, err
		}
		return Requested, nil
	}
	if r.RevocationState == string(Requested) || r.RevocationState == string(CleanupUnknown) {
		if err = advance(Stopping); err != nil {
			return RevocationState(r.RevocationState), err
		}
		return Stopping, nil
	}
	s.mu.Lock()
	active, known := len(s.active[key]), s.known[key]
	s.mu.Unlock()
	if active > 0 {
		return Stopping, nil
	}
	if !known {
		if err = advance(CleanupUnknown); err != nil {
			return Stopping, err
		}
		return CleanupUnknown, nil
	}
	if err = advance(Revoked); err != nil {
		return Stopping, err
	}
	return Revoked, nil
}

// ReportDispatchCleanupUnknown inhibits only the verified client's already
// admitted dispatch. It cannot approve access or report a completed revocation,
// and does not impersonate the separately authenticated human administrator.
func (s *Service) ReportDispatchCleanupUnknown(ctx context.Context, grantID string) (RevocationState, error) {
	c, err := s.client(ctx)
	if err != nil {
		return "", err
	}
	ns, err := s.namespace(ctx)
	if err != nil {
		return "", err
	}
	key := ns + ":" + grantID
	s.mu.Lock()
	bound := false
	for _, binding := range s.bindings[key] {
		if binding.ID == c.ID && binding.SessionID == c.SessionID {
			bound = true
			break
		}
	}
	if !bound {
		s.mu.Unlock()
		return "", fmt.Errorf("verified bound active dispatch required")
	}
	s.blocked[key] = true
	cancellations := s.cancellationsLocked(key)
	s.mu.Unlock()
	for _, cancel := range cancellations {
		cancel()
	}
	r, err := s.lookup(ctx, grantID, c.ID)
	if err != nil {
		return "", err
	}
	if r.GrantID != grantID || r.ClientID != c.ID || (!r.permanent() && r.SessionID != c.SessionID) || r.Decision == "" || r.Decision == string(Deny) {
		return "", fmt.Errorf("verified bound active dispatch required")
	}

	if r.RevocationState == string(CleanupUnknown) {
		return CleanupUnknown, nil
	}
	if r.RevocationState == string(Revoked) {
		return "", fmt.Errorf("completed revocation cannot become uncertain dispatch")
	}
	for _, next := range []RevocationState{Requested, Stopping, CleanupUnknown} {
		if next == Requested && r.RevocationState != "" || next == Stopping && r.RevocationState != string(Requested) {
			continue
		}
		previous := r
		r.RevocationState = string(next)
		r.Revision++
		if err = s.write(ctx, "revoke", c.ID, r, &previous); err != nil {
			return RevocationState(previous.RevocationState), err
		}
	}
	return CleanupUnknown, nil
}

// CleanupUnknown is used by the host after helper disconnect, restart or cleanup
// uncertainty. It cannot convert uncertainty into a completed revocation.
func (s *Service) CleanupUnknown(ctx context.Context, grantID string) (RevocationState, error) {
	a, err := s.actor(ctx)
	if err != nil {
		return "", err
	}
	ns, err := s.namespace(ctx)
	if err != nil {
		return "", err
	}
	s.inhibit(ns + ":" + grantID)
	r, err := s.lookup(ctx, grantID, a.ID)
	if err != nil {
		return "", err
	}
	if r.GrantID != grantID || r.RevocationState != string(Stopping) {
		return "", fmt.Errorf("stopping grant required")
	}
	previous := r
	r.RevocationState = string(CleanupUnknown)
	r.Revision++
	if err = s.write(ctx, "revoke", a.ID, r, &previous); err != nil {
		return Stopping, err
	}
	return CleanupUnknown, nil
}
func (s *Service) invoke(ctx context.Context, pkg, method string, input any, authority data.ConsentAuthority) (any, error) {
	ctx = data.WithConsentAuthority(ctx, authority)
	var outcome handler.Outcome
	result, err := s.options.Invoke(ctx, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + pkg, Name: pkg}, Route: spec.RouteRef{Method: method, Path: "/internal/data/" + pkg}}, Input: input, Completion: func(actual handler.Outcome) { outcome = actual }})
	if err != nil {
		return nil, err
	}
	if method != "GET" && !outcome.CommitConfirmed() {
		return nil, fmt.Errorf("consent durability unconfirmed; reconcile before dispatch")
	}
	return result, nil
}

// The caller holds registrymu only while copying cancellation handles. Context
// cancellation and callbacks execute after unlock to keep lock order explicit.
func (s *Service) cancellationsLocked(key string) []context.CancelFunc {
	cancellations := make([]context.CancelFunc, 0, len(s.active[key]))
	for _, cancel := range s.active[key] {
		cancellations = append(cancellations, cancel)
	}
	return cancellations
}
func (s *Service) inhibit(key string) {
	s.mu.Lock()
	s.blocked[key] = true
	cancellations := s.cancellationsLocked(key)
	s.mu.Unlock()
	for _, cancel := range cancellations {
		cancel()
	}
}
