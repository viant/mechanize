package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/applicationpolicyread"
	"github.com/viant/mechanize/data/applicationpolicywrite"
	"github.com/viant/xdatly/handler"
)

type ApplicationAccessEntry struct {
	BundleID    string   `json:"bundleID"`
	DisplayName string   `json:"displayName"`
	Modes       []string `json:"modes"`
	Status      string   `json:"status"`
	Detail      string   `json:"detail"`
}
type ApplicationAccessSnapshot struct {
	Revision int                      `json:"revision"`
	Policy   data.ApplicationPolicy   `json:"policy"`
	Rows     []ApplicationAccessEntry `json:"rows"`
}
type applicationPolicyGate struct {
	mu                 sync.Mutex
	generation         uint64
	next               uint64
	editing, uncertain bool
	active             map[uint64]context.CancelFunc
}
type applicationAccessService struct {
	invoke   func(context.Context, auth.Principal, exec.ComponentRequest) (any, error)
	enrolled func(context.Context, auth.Principal) (User, error)
	mu       sync.Mutex
	gates    map[string]*applicationPolicyGate
}

func (s *applicationAccessService) gate(namespace string) *applicationPolicyGate {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gates == nil {
		s.gates = map[string]*applicationPolicyGate{}
	}
	g := s.gates[namespace]
	if g == nil {
		g = &applicationPolicyGate{active: map[uint64]context.CancelFunc{}}
		s.gates[namespace] = g
	}
	return g
}
func applicationPolicyRequest(name, method string, input any, complete func(handler.Outcome)) exec.ComponentRequest {
	return exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + name, Name: name}, Route: spec.RouteRef{Method: method, Path: "/internal/data/" + name}}, Input: input, Completion: complete}
}
func (s *applicationAccessService) read(ctx context.Context, p auth.Principal) (ApplicationAccessSnapshot, string, error) {
	u, err := s.enrolled(ctx, p)
	if err != nil {
		return ApplicationAccessSnapshot{}, "", err
	}
	in := &applicationpolicyread.ReadApplicationPolicyInput{}
	in.SetNamespace(p.Namespace)
	value, err := s.invoke(ctx, p, applicationPolicyRequest("applicationpolicyread", "GET", in, nil))
	if err != nil {
		return ApplicationAccessSnapshot{}, "", err
	}
	out, ok := value.(*applicationpolicyread.ReadApplicationPolicyOutput)
	if !ok || len(out.Data) > 1 {
		return ApplicationAccessSnapshot{}, "", errors.New("invalid application policy response")
	}
	snapshot := ApplicationAccessSnapshot{Policy: data.ApplicationPolicy{DesktopWide: u.DesktopAccess, Applications: []data.ApplicationPolicyRule{}}, Rows: []ApplicationAccessEntry{}}
	created := ""
	if len(out.Data) == 0 {
		if !u.DesktopAccess {
			for _, id := range u.NativeBundles {
				modes := []string{"observe", "control"}
				if u.RecordingAllowed {
					modes = append(modes, "record")
				}
				snapshot.Policy.Applications = append(snapshot.Policy.Applications, data.ApplicationPolicyRule{BundleID: id, DisplayName: id, Modes: modes})
			}
		}
	} else {
		row := out.Data[0]
		if row == nil || row.Namespace == nil || *row.Namespace != p.Namespace || row.Id == nil || *row.Id != data.ApplicationPolicyID || row.Revision == nil || *row.Revision < 1 || row.PolicyJson == nil || row.CreatedAt == nil {
			return snapshot, "", errors.New("invalid application policy identity")
		}
		snapshot.Revision = *row.Revision
		created = *row.CreatedAt
		if err = json.Unmarshal([]byte(*row.PolicyJson), &snapshot.Policy); err != nil {
			return snapshot, "", err
		}
	}
	snapshot.Policy, err = data.CanonicalApplicationPolicy(snapshot.Policy)
	if err != nil {
		return snapshot, "", err
	}
	for _, rule := range snapshot.Policy.Applications {
		status := "Allowed"
		if len(rule.Modes) == 0 {
			status = "Blocked"
		}
		snapshot.Rows = append(snapshot.Rows, ApplicationAccessEntry{BundleID: rule.BundleID, DisplayName: rule.DisplayName, Modes: rule.Modes, Status: status, Detail: "Application policy; session trust and macOS permissions also apply"})
	}
	return snapshot, created, nil
}
func (s *applicationAccessService) snapshot(ctx context.Context, p auth.Principal) (ApplicationAccessSnapshot, error) {
	snapshot, _, err := s.read(ctx, p)
	if err == nil {
		g := s.gate(p.Namespace)
		g.mu.Lock()
		if !g.editing && g.uncertain {
			g.uncertain = false
			g.generation++
		}
		g.mu.Unlock()
	}
	return snapshot, err
}
func policyAllowsScope(policy data.ApplicationPolicy, scope consent.Scope, mode consent.Mode) bool {
	switch scope.Kind {
	case "application", "window":
		return policy.Allows(scope.BundleID, string(mode))
	case "origin":
		return policy.Allows("com.google.Chrome", string(mode))
	case "desktop":
		if !policy.DesktopWide {
			return false
		}
		for _, rule := range policy.Applications {
			if !policy.Allows(rule.BundleID, string(mode)) {
				return false
			}
		}
		return true
	}
	return false
}
func (s *applicationAccessService) admission(ctx context.Context, p auth.Principal, scope consent.Scope, mode consent.Mode) (*applicationPolicyGate, uint64, error) {
	g := s.gate(p.Namespace)
	g.mu.Lock()
	generation := g.generation
	blocked := g.editing || g.uncertain
	g.mu.Unlock()
	if blocked {
		return nil, 0, errors.New("application access is changing; refresh the permissions panel")
	}
	current, _, err := s.read(ctx, p)
	if err != nil {
		return nil, 0, err
	}
	if !policyAllowsScope(current.Policy, scope, mode) {
		return nil, 0, errors.New("application access disabled in the Applications tab")
	}
	return g, generation, nil
}
func (g *applicationPolicyGate) retain(generation uint64, lease *consent.Lease) (*consent.Lease, error) {
	bound, cancel := context.WithCancel(lease.Context)
	g.mu.Lock()
	if g.generation != generation || g.editing || g.uncertain {
		g.mu.Unlock()
		cancel()
		lease.Release()
		return nil, errors.New("application policy changed before dispatch")
	}
	g.next++
	id := g.next
	g.active[id] = cancel
	g.mu.Unlock()
	var once sync.Once
	return &consent.Lease{Context: bound, Release: func() {
		once.Do(func() { cancel(); g.mu.Lock(); delete(g.active, id); g.mu.Unlock(); lease.Release() })
	}}, nil
}
func (s *applicationAccessService) update(ctx context.Context, p auth.Principal, expected int, policy data.ApplicationPolicy) (ApplicationAccessSnapshot, error) {
	if !auth.NativeHuman(ctx) || expected < 0 {
		return ApplicationAccessSnapshot{}, auth.ErrUnauthorized
	}
	u, err := s.enrolled(ctx, p)
	if err != nil {
		return ApplicationAccessSnapshot{}, err
	}
	policy, err = data.CanonicalApplicationPolicy(policy)
	if err != nil {
		return ApplicationAccessSnapshot{}, err
	}
	if policy.DesktopWide && !u.DesktopAccess {
		return ApplicationAccessSnapshot{}, auth.ErrUnauthorized
	}
	for _, rule := range policy.Applications {
		allowed := u.DesktopAccess
		for _, id := range u.NativeBundles {
			allowed = allowed || id == rule.BundleID
		}
		if !allowed && len(rule.Modes) > 0 {
			return ApplicationAccessSnapshot{}, auth.ErrUnauthorized
		}
		for _, mode := range rule.Modes {
			if mode == "record" && !u.RecordingAllowed {
				return ApplicationAccessSnapshot{}, auth.ErrUnauthorized
			}
		}
	}
	current, created, err := s.read(ctx, p)
	if err != nil {
		return current, err
	}
	if current.Revision != expected {
		return current, errors.New("application policy changed; refresh before saving")
	}
	raw, err := data.ApplicationPolicyJSON(policy)
	if err != nil {
		return current, err
	}
	g := s.gate(p.Namespace)
	g.mu.Lock()
	if g.editing {
		g.mu.Unlock()
		return current, errors.New("application policy update already in progress")
	}
	g.editing = true
	g.generation++
	cancels := make([]context.CancelFunc, 0, len(g.active))
	for _, cancel := range g.active {
		cancels = append(cancels, cancel)
	}
	g.mu.Unlock()
	// Cancel before entering the generated writer; never hold registry locks over database I/O.
	for _, cancel := range cancels {
		cancel()
	}
	confirmed := false
	defer func() { g.mu.Lock(); g.editing = false; g.uncertain = !confirmed; g.mu.Unlock() }()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if expected == 0 {
		created = now
	}
	ctx = data.WithApplicationPolicyAuthority(ctx, data.ApplicationPolicyAuthority{Namespace: p.Namespace, ExpectedRevision: expected, PolicyJSON: raw, CreatedAt: created, UpdatedAt: now})
	row := &applicationpolicywrite.PolicyRecord{}
	id := data.ApplicationPolicyID
	row.SetNamespace(&p.Namespace)
	row.SetId(&id)
	row.SetRevision(&expected)
	row.SetPolicyJson(&raw)
	row.SetCreatedAt(&created)
	row.SetUpdatedAt(&now)
	in := &applicationpolicywrite.WriteApplicationPolicyInput{}
	in.SetNamespace(p.Namespace)
	in.SetExpectedRevision(expected)
	in.SetApplicationpolicywrite([]*applicationpolicywrite.PolicyRecord{row})
	var outcome handler.Outcome
	_, err = s.invoke(ctx, p, applicationPolicyRequest("applicationpolicywrite", "PATCH", in, func(value handler.Outcome) { outcome = value }))
	if err != nil {
		return current, err
	}
	if !outcome.CommitConfirmed() {
		return current, errors.New("application policy durability unconfirmed; refresh before continuing")
	}
	confirmed = true
	result, _, err := s.read(ctx, p)
	if err == nil && result.Revision != expected+1 {
		return result, fmt.Errorf("application policy changed after saving; refresh required")
	}
	return result, err
}
