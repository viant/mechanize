// Package objective evaluates typed business predicates without dispatching UI actions.
package objective

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

type Truth string

const (
	True    Truth = "true"
	False   Truth = "false"
	Unknown Truth = "unknown"
)

type Authority string

const (
	Visual        Authority = "visual"
	Observational Authority = "observational"
	Authoritative Authority = "authoritative"
)

type Evidence struct {
	Kind        string `json:"kind"`
	Reference   string `json:"reference"`
	BusinessKey string `json:"businessKey,omitempty"`
}
type Result struct {
	Truth      Truth      `json:"truth"`
	Authority  Authority  `json:"authority"`
	ObservedAt time.Time  `json:"observedAt"`
	Evidence   []Evidence `json:"evidence"`
	Reason     string     `json:"reason,omitempty"`
}

// Adapter is an enrolled read-only source of outcome evidence. Implementations
// cannot obtain dispatch authority from this evaluator.
type Adapter interface {
	Evaluate(context.Context, auth.Principal, string, map[string]model.Value) (Result, error)
}
type Enrollment struct {
	Adapter           Adapter
	MaximumAuthority  Authority
	AllowedPredicates map[string]bool
	// BusinessKeyInput names the typed string argument bound to every outcome receipt.
	BusinessKeyInput string
}
type Evaluator struct {
	adapters map[string]Enrollment
	now      func() time.Time
}

func New(adapters map[string]Enrollment) (*Evaluator, error) {
	owned := map[string]Enrollment{}
	for name, a := range adapters {
		if name == "" || a.Adapter == nil || rank(a.MaximumAuthority) == 0 || len(a.AllowedPredicates) == 0 {
			return nil, errors.New("qualified adapter and predicate set required")
		}
		copy := a
		copy.AllowedPredicates = map[string]bool{}
		for p, allowed := range a.AllowedPredicates {
			copy.AllowedPredicates[p] = allowed
		}
		owned[name] = copy
	}
	return &Evaluator{adapters: owned, now: time.Now}, nil
}
func rank(a Authority) int {
	switch a {
	case Visual:
		return 1
	case Observational:
		return 2
	case Authoritative:
		return 3
	}
	return 0
}
func (e *Evaluator) Evaluate(ctx context.Context, p auth.Principal, predicate model.Predicate, bindings map[string]model.Value) (Result, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
		return Result{}, auth.ErrUnauthorized
	}
	if predicate.Kind != "adapter" {
		return Result{Truth: Unknown, Reason: "predicate implementation is not qualified"}, nil
	}
	adapter, ok := e.adapters[predicate.Adapter]
	if !ok || !adapter.AllowedPredicates[predicate.Name] {
		return Result{Truth: Unknown, Reason: "adapter predicate is not enrolled"}, nil
	}
	required := Authority(predicate.RequiredAuthority)
	if rank(required) == 0 {
		return Result{}, errors.New("explicit predicate authority required")
	}
	budget := predicate.TimeoutMs
	if budget <= 0 || budget > 30000 {
		return Result{}, errors.New("predicate deadline must be 1...30000ms")
	}
	inputs := map[string]model.Value{}
	for name, value := range predicate.Inputs {
		resolved, err := model.ResolveValue(value, bindings)
		if err != nil {
			return Result{}, err
		}
		inputs[name] = resolved
	}
	keyInput := adapter.BusinessKeyInput
	if keyInput == "" {
		keyInput = "businessKey"
	}
	expectedKey := inputs[keyInput]
	if required == Authoritative && (expectedKey.Kind != model.StringValue || expectedKey.String == "") {
		return Result{Truth: Unknown, Reason: "exact business key input is required"}, nil
	}
	bounded, cancel := context.WithTimeout(ctx, time.Duration(budget)*time.Millisecond)
	defer cancel()
	result, err := adapter.Adapter.Evaluate(bounded, p, predicate.Name, inputs)
	if bounded.Err() != nil {
		return Result{Truth: Unknown, Reason: "outcome source deadline exceeded"}, nil
	}
	if err != nil {
		return Result{Truth: Unknown, Reason: "outcome source unavailable"}, nil
	}
	if result.Truth != True && result.Truth != False && result.Truth != Unknown {
		return Result{}, errors.New("adapter returned invalid truth state")
	}
	if result.Truth == Unknown {
		return result, nil
	}
	if rank(result.Authority) == 0 || rank(result.Authority) > rank(adapter.MaximumAuthority) {
		return Result{}, errors.New("adapter claimed unqualified authority")
	}
	if result.Authority == Authoritative && (expectedKey.Kind != model.StringValue || expectedKey.String == "") {
		return Result{Truth: Unknown, Reason: "authoritative evidence requires exact business key input"}, nil
	}
	if rank(result.Authority) < rank(required) {
		return Result{Truth: Unknown, Authority: result.Authority, Reason: "evidence authority is insufficient"}, nil
	}
	age := e.now().Sub(result.ObservedAt)
	if result.ObservedAt.IsZero() || age < 0 || predicate.FreshnessMs <= 0 || age > time.Duration(predicate.FreshnessMs)*time.Millisecond {
		return Result{Truth: Unknown, Reason: "outcome evidence is stale or untimed"}, nil
	}
	if len(result.Evidence) == 0 {
		return Result{Truth: Unknown, Reason: "outcome evidence is missing"}, nil
	}
	for _, evidence := range result.Evidence {
		if evidence.Kind == "" || evidence.Reference == "" {
			return Result{Truth: Unknown, Reason: "outcome evidence is incomplete"}, nil
		}
		if result.Authority == Authoritative && evidence.BusinessKey != expectedKey.String {
			return Result{Truth: Unknown, Reason: "outcome evidence business key mismatch"}, nil
		}
	}
	return result, nil
}

// RequireBusinessSuccess never treats unavailable evidence as false or success.
func RequireBusinessSuccess(result Result) error {
	if result.Truth != True || result.Authority != Authoritative || result.ObservedAt.IsZero() || result.ObservedAt.After(time.Now()) || len(result.Evidence) == 0 {
		return fmt.Errorf("business objective is not verified: %s", result.Truth)
	}
	key := result.Evidence[0].BusinessKey
	if key == "" {
		return errors.New("business evidence key required")
	}
	for _, e := range result.Evidence {
		if e.Kind == "" || e.Reference == "" || e.BusinessKey != key {
			return errors.New("complete exact-key business evidence required")
		}
	}
	return nil
}
