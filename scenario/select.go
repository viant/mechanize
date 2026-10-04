// Package scenario selects only from an already discovered, authorized catalogue.
// Selection is a proposal; it never executes or grants permission.
package scenario

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

type Cohort struct {
	Key               string    `json:"key"`
	Qualified         bool      `json:"qualified"`
	IndependentTrials int       `json:"independentTrials"`
	VerifiedSuccesses int       `json:"verifiedSuccesses"`
	PeriodStart       time.Time `json:"periodStart"`
	PeriodEnd         time.Time `json:"periodEnd"`
}
type Requirements struct {
	Surface      model.Surface `json:"surface"`
	Profile      string        `json:"profile"`
	Version      string        `json:"version"`
	Capabilities []string      `json:"capabilities"`
	Permissions  []string      `json:"permissions"`
	Verification string        `json:"verification"`
	CohortKey    string        `json:"cohortKey"`
}
type Candidate struct {
	Namespace     string                           `json:"namespace"`
	ID            string                           `json:"id"`
	Revision      string                           `json:"revision"`
	ObjectiveHash string                           `json:"objectiveHash"`
	Entity        map[string]model.Value           `json:"entity"`
	Inputs        map[string]model.InputDefinition `json:"inputs"`
	Requirements  Requirements                     `json:"requirements"`
	Qualified     Cohort                           `json:"qualified"`
	ObservedAt    time.Time                        `json:"observedAt"`
	// Specificity is the count of exact declared constraints, not model confidence.
	ExactConstraints []string `json:"exactConstraints"`
}
type Request struct {
	ObjectiveHash string
	Entity        map[string]model.Value
	InputSchema   map[string]model.InputDefinition
	Inputs        map[string]model.Value
	Environment   Requirements
	Now           time.Time
	MaxAge        time.Duration
}
type Rejection struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}
type Selection struct {
	Namespace string      `json:"namespace"`
	Status    string      `json:"status"`
	Candidate *Candidate  `json:"candidate,omitempty"`
	Rejected  []Rejection `json:"rejected,omitempty"`
	Reason    string      `json:"reason,omitempty"`
}

func Select(ctx context.Context, r Request, candidates []Candidate) (Selection, error) {
	p, err := auth.FromContext(ctx)
	if err != nil {
		return Selection{}, err
	}
	out := Selection{Namespace: p.Namespace, Status: "needsAttention"}
	if r.ObjectiveHash == "" || len(r.Entity) == 0 || r.Now.IsZero() || r.MaxAge <= 0 || r.MaxAge > 24*time.Hour || len(candidates) > 1000 {
		return out, fmt.Errorf("selection requires objective, entity, bounded fresh state and at most 1000 catalogue candidates")
	}
	for k, v := range r.Inputs {
		d, ok := r.InputSchema[k]
		if !ok || v.Kind != d.Type || v.Validate() != nil {
			return out, fmt.Errorf("input %s does not match the requested typed schema", k)
		}
	}
	for k, d := range r.InputSchema {
		if d.Required {
			if _, ok := r.Inputs[k]; !ok {
				return out, fmt.Errorf("required input %s is missing", k)
			}
		}
	}
	eligible := []Candidate{}
	seen := map[string]bool{}
	for _, c := range candidates {
		reason := ""
		switch {
		case c.Namespace != p.Namespace:
			reason = "catalogue candidate is outside the verified namespace"
		case c.ID == "" || c.Revision == "" || seen[c.ID+"/"+c.Revision]:
			reason = "missing or duplicate catalogue identity"
		case c.ObjectiveHash != r.ObjectiveHash || !reflect.DeepEqual(c.Entity, r.Entity):
			reason = "objective or business entity differs"
		case !reflect.DeepEqual(c.Inputs, r.InputSchema):
			reason = "input schema differs"
		case c.Requirements.Surface != r.Environment.Surface || c.Requirements.Profile == "" || c.Requirements.Profile != r.Environment.Profile || c.Requirements.Version == "" || c.Requirements.Version != r.Environment.Version:
			reason = "surface, semantics profile or version differs"
		case c.Requirements.Verification == "" || c.Requirements.Verification != r.Environment.Verification:
			reason = "required verification contract is unavailable"
		case !subset(c.Requirements.Capabilities, r.Environment.Capabilities):
			reason = "required capability is unavailable"
		case !subset(c.Requirements.Permissions, r.Environment.Permissions):
			reason = "required permission is unavailable"
		case !c.Qualified.Qualified || c.Qualified.Key == "" || c.Qualified.Key != r.Environment.CohortKey || c.Requirements.CohortKey != c.Qualified.Key:
			reason = "exact cohort is not qualified"
		case c.Qualified.IndependentTrials < 1 || c.Qualified.VerifiedSuccesses < 0 || c.Qualified.VerifiedSuccesses > c.Qualified.IndependentTrials || c.Qualified.PeriodStart.IsZero() || c.Qualified.PeriodEnd.Before(c.Qualified.PeriodStart) || c.Qualified.PeriodEnd.After(r.Now):
			reason = "measured cohort evidence is invalid or unmeasured"
		case c.ObservedAt.IsZero() || c.ObservedAt.After(r.Now) || r.Now.Sub(c.ObservedAt) > r.MaxAge:
			reason = "candidate state is stale; rediscover before selecting"
		}
		seen[c.ID+"/"+c.Revision] = true
		if reason == "" {
			for _, scope := range c.Requirements.Permissions {
				if !p.HasScope(scope) {
					reason = "verified principal lacks required permission " + scope
					break
				}
			}
		}
		if reason != "" {
			out.Rejected = append(out.Rejected, Rejection{c.ID, reason})
			continue
		}
		// Clone caller-owned maps so the result does not alias the catalogue.
		data, _ := json.Marshal(c)
		var copy Candidate
		_ = json.Unmarshal(data, &copy)
		eligible = append(eligible, copy)
	}
	sort.SliceStable(eligible, func(i, j int) bool { return compare(eligible[i], eligible[j]) > 0 })
	if len(eligible) == 0 {
		out.Reason = "no eligible scenario; discover a qualified scenario matching objective, entity and current environment"
		return out, nil
	}
	if len(eligible) > 1 && compare(eligible[0], eligible[1]) == 0 {
		out.Reason = "equally eligible scenarios are ambiguous; select an explicit catalogue revision"
		return out, nil
	}
	out.Status = "selected"
	out.Candidate = &eligible[0]
	return out, nil
}
func subset(need, have []string) bool {
	for _, n := range need {
		found := false
		for _, h := range have {
			if n == h {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func specificity(c Candidate) int {
	seen := map[string]bool{}
	for _, v := range c.ExactConstraints {
		if v != "" {
			seen[v] = true
		}
	}
	return len(seen)
}
func compare(a, b Candidate) int {
	if specificity(a) != specificity(b) {
		if specificity(a) > specificity(b) {
			return 1
		}
		return -1
	}
	if !a.ObservedAt.Equal(b.ObservedAt) {
		if a.ObservedAt.After(b.ObservedAt) {
			return 1
		}
		return -1
	}
	x, y := lower(a.Qualified), lower(b.Qualified)
	if x > y {
		return 1
	}
	if x < y {
		return -1
	}
	return 0
}

// lower ranks qualified independent measured cohorts; it is not an LLM probability.
func lower(c Cohort) float64 {
	n := float64(c.IndependentTrials)
	p := float64(c.VerifiedSuccesses) / n
	z := 1.96
	return (p + z*z/(2*n) - z*math.Sqrt(p*(1-p)/n+z*z/(4*n*n))) / (1 + z*z/n)
}
