package host

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	get "github.com/viant/mechanize/data/chromeretirementget"
	write "github.com/viant/mechanize/data/chromeretirementwrite"
	"github.com/viant/xdatly/handler"
	"reflect"
)

// commitChromeRetirement invokes only generated components. The supplied private
// invoker must hold the lifecycle admission guard and durable user scope across
// all calls. Uncertain commits are returned as errors, never retried here.
func commitChromeRetirement(ctx context.Context, invoke committedComponentInvoker) (*get.Retirement, error) {
	fail := func() (*get.Retirement, error) {
		return nil, errors.New("Chrome retirement commit/readback is unconfirmed")
	}
	a, err := data.RequireChromeRetirementAuthority(ctx)
	if err != nil || invoke == nil {
		return fail()
	}
	p, err := auth.FromContext(ctx)
	if err != nil {
		return fail()
	}
	input, err := chromeRetirementInput(ctx)
	if err != nil {
		return fail()
	}
	call := func(pkg, name, method string, in any, completion func(handler.Outcome)) (any, error) {
		return invoke(ctx, p, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + pkg, Name: name}, Route: spec.RouteRef{Method: method, Path: "/internal/data/" + pkg}}, Input: in, Completion: completion})
	}
	read := func() (*get.Retirement, error) {
		in := &get.LoadChromeRetirementInput{}
		in.SetNamespace(a.Namespace)
		in.SetClientID(a.ClientID)
		in.SetTransitionID(a.TransitionID)
		value, err := call("chromeretirementget", "LoadChromeRetirement", "GET", in, nil)
		if err != nil {
			return nil, err
		}
		out, ok := value.(*get.LoadChromeRetirementOutput)
		if !ok || out == nil || len(out.Data) > 1 {
			return fail()
		}
		if len(out.Data) == 0 {
			return nil, nil
		}
		if out.Data[0] == nil {
			return fail()
		}
		return out.Data[0], nil
	}
	prior, err := read()
	if err != nil {
		return fail()
	}
	// An acknowledgement may have been lost after a confirmed phase was stored.
	// Adopt only an exact intended/prepared readback; never issue a duplicate PATCH.
	if prior != nil && prior.Phase != nil && *prior.Phase == a.Phase && prior.Revision != nil && *prior.Revision == a.PriorRevision+1 && (a.Phase == "intended" || a.Phase == "prepared") {
		var baseline *get.Retirement
		if a.PriorRevision > 0 {
			raw, e := json.Marshal(prior)
			if e != nil {
				return fail()
			}
			if json.Unmarshal(raw, &baseline) != nil {
				return fail()
			}
			previous := make([]*get.Audit, 0, a.PriorRevision)
			for _, audit := range baseline.Audit {
				if audit == nil || audit.Id == nil {
					return fail()
				}
				if *audit.Id != a.AuditID {
					previous = append(previous, audit)
				}
			}
			baseline.Audit = previous
		}
		if !retirementReadbackMatches(input.WriteChromeRetirement[0], prior, baseline, a.PriorRevision+1) {
			return fail()
		}
		if _, err = data.RequireChromeRetirementAuthority(ctx); err != nil {
			return fail()
		}
		return prior, nil
	}
	if a.PriorRevision == 0 {
		if prior != nil {
			return fail()
		}
	} else if prior == nil || prior.Revision == nil || *prior.Revision != a.PriorRevision || prior.Phase == nil || *prior.Phase != data.ChromeRetirementPreviousPhase(a.Phase) {
		return fail()
	}
	// Detach prior evidence: a callback must not be able to mutate the baseline
	// while satisfying the post-write comparison with shared pointers.
	priorJSON, err := json.Marshal(prior)
	if err != nil {
		return fail()
	}
	var baseline *get.Retirement
	if json.Unmarshal(priorJSON, &baseline) != nil {
		return fail()
	}
	var outcome handler.Outcome
	if _, err = call("chromeretirementwrite", "WriteChromeRetirement", "PATCH", input, func(v handler.Outcome) { outcome = v }); err != nil || !outcome.CommitConfirmed() {
		return fail()
	}
	stored, err := read()
	if err != nil || !retirementReadbackMatches(input.WriteChromeRetirement[0], stored, baseline, a.PriorRevision+1) {
		return fail()
	}
	if _, err = data.RequireChromeRetirementAuthority(ctx); err != nil {
		return fail()
	}
	return stored, nil
}

func retirementJSON(value any) map[string]json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(raw, &result) != nil {
		return nil
	}
	return result
}
func retirementReadbackMatches(expected *write.Retirement, stored, prior *get.Retirement, revision int) bool {
	if expected == nil || stored == nil || stored.Revision == nil || *stored.Revision != revision {
		return false
	}
	want, actual := retirementJSON(expected), retirementJSON(stored)
	if want == nil || actual == nil {
		return false
	}
	for key, value := range want {
		if key == "revision" || key == "audit" || key == "manifests" {
			continue
		}
		if string(value) != string(actual[key]) {
			return false
		}
	}
	if len(expected.Audit) != 1 || len(stored.Audit) != revision {
		return false
	}
	audits := map[string]json.RawMessage{}
	for _, row := range stored.Audit {
		if row == nil || row.Id == nil {
			return false
		}
		if _, exists := audits[*row.Id]; exists {
			return false
		}
		raw, err := json.Marshal(row)
		if err != nil {
			return false
		}
		audits[*row.Id] = raw
	}
	checkAudit := func(row any) bool {
		m := retirementJSON(row)
		if m == nil {
			return false
		}
		var id string
		if json.Unmarshal(m["id"], &id) != nil {
			return false
		}
		raw, err := json.Marshal(row)
		return err == nil && string(audits[id]) == string(raw)
	}
	if !checkAudit(expected.Audit[0]) {
		return false
	}
	if prior != nil {
		if len(prior.Audit) != revision-1 {
			return false
		}
		for _, row := range prior.Audit {
			if !checkAudit(row) {
				return false
			}
		}
	}
	var wantedManifests any = expected.Manifests
	if expected.Phase != nil && (*expected.Phase == "released" || *expected.Phase == "adopted") {
		if prior == nil {
			return false
		}
		wantedManifests = prior.Manifests
	}
	// Both generated graphs expose the same manifest contract. Compare by stable
	// manifest ID rather than relying on database row ordering.
	normalize := func(rows any) (map[string]string, bool) {
		raw, err := json.Marshal(rows)
		if err != nil {
			return nil, false
		}
		var list []map[string]json.RawMessage
		if json.Unmarshal(raw, &list) != nil {
			return nil, false
		}
		result := map[string]string{}
		for _, r := range list {
			var id string
			if json.Unmarshal(r["id"], &id) != nil || id == "" {
				return nil, false
			}
			if _, exists := result[id]; exists {
				return nil, false
			}
			v, err := json.Marshal(r)
			if err != nil {
				return nil, false
			}
			result[id] = string(v)
		}
		return result, true
	}
	wm, ok := normalize(wantedManifests)
	if !ok {
		return false
	}
	sm, ok := normalize(stored.Manifests)
	return ok && reflect.DeepEqual(wm, sm)
}
