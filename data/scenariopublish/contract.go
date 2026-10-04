package scenariopublish

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"

	"github.com/viant/mechanize/model"
	selector "github.com/viant/mechanize/scenario"
)

const MaximumDraftBytes = 128 << 10

type Provenance struct {
	RecordingID  string   `json:"recordingId"`
	Reviewed     bool     `json:"reviewed"`
	Verified     bool     `json:"verified"`
	Gaps         []string `json:"gaps,omitempty"`
	ReviewedGaps []string `json:"reviewedGaps,omitempty"`
	Issues       []string `json:"issues,omitempty"`
}

// DraftDefinition contains reusable symbols, never current inputs or qualification.
// Entity constraints refer to declared inputs, resolved transiently at selection.
type DraftDefinition struct {
	SchemaVersion int                    `json:"schemaVersion"`
	ID            string                 `json:"id"`
	Revision      string                 `json:"revision"`
	Plan          model.Plan             `json:"plan"`
	Entity        map[string]model.Value `json:"entity"`
	Requirements  selector.Requirements  `json:"requirements"`
	Provenance    Provenance             `json:"provenance"`
}

func ValidID(id string) bool {
	if len(id) < 1 || len(id) > 96 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
func Digest(content []byte) string { sum := sha256.Sum256(content); return hex.EncodeToString(sum[:]) }
func ObjectiveHash(plan model.Plan) (string, error) {
	if plan.Objective == nil {
		return "", errors.New("scenario objective required")
	}
	content, err := json.Marshal(plan.Objective)
	return Digest(content), err
}
func Canonical(def DraftDefinition) ([]byte, error) {
	if err := ValidateDefinition(def); err != nil {
		return nil, err
	}
	content, err := json.Marshal(def)
	if len(content) > MaximumDraftBytes {
		return nil, errors.New("scenario draft byte bound exceeded")
	}
	return content, err
}
func DecodeCanonical(content string) (DraftDefinition, error) {
	var def DraftDefinition
	if len(content) > MaximumDraftBytes {
		return def, errors.New("scenario draft byte bound exceeded")
	}
	decoder := json.NewDecoder(strings.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&def); err != nil {
		return def, err
	}
	canonical, err := Canonical(def)
	if err != nil {
		return def, err
	}
	if !bytes.Equal(canonical, []byte(content)) {
		return def, errors.New("scenario definition is not canonical")
	}
	return def, nil
}
func ValidateDefinition(def DraftDefinition) error {
	if def.SchemaVersion != 1 || !ValidID(def.ID) || !ValidID(def.Revision) || !ValidID(def.Provenance.RecordingID) || len(def.Entity) == 0 || len(def.Entity) > 64 {
		return errors.New("bounded scenario revision, recording provenance and entity specification required")
	}
	if err := def.Plan.Validate(); err != nil {
		return err
	}
	if def.Plan.Objective == nil {
		return errors.New("scenario objective required")
	}
	if len(def.Plan.Inputs) > 128 || len(def.Plan.Steps) > 256 || len(def.Plan.Bindings) > 128 || len(def.Plan.Surfaces) > 16 {
		return errors.New("scenario IR bound exceeded")
	}
	for _, input := range def.Plan.Inputs {
		if input.Default != nil {
			return errors.New("scenario inputs cannot persist defaults")
		}
	}
	if def.Plan.Name != "" && !ValidID(def.Plan.Name) {
		return errors.New("scenario plan name must be a bounded structural identifier")
	}
	if def.Plan.Constraints != nil && len(def.Plan.Constraints.FileRoots) > 0 {
		return errors.New("scenario cannot persist captured filesystem roots")
	}
	req := def.Requirements
	if req.Profile == "" || len(req.Profile) > 128 || req.Version == "" || len(req.Version) > 128 || req.Verification == "" || len(req.Verification) > 128 || req.CohortKey == "" || len(req.CohortKey) > 128 || len(req.Capabilities) > 64 || len(req.Permissions) > 64 {
		return errors.New("exact bounded profile, version, verification and cohort declarations required")
	}
	if err := validateSurface(req.Surface); err != nil {
		return err
	}
	for _, items := range [][]string{req.Capabilities, req.Permissions, def.Provenance.Gaps, def.Provenance.ReviewedGaps, def.Provenance.Issues} {
		if len(items) > 128 {
			return errors.New("scenario declaration bound exceeded")
		}
		for _, item := range items {
			if len(item) == 0 || len(item) > 128 {
				return errors.New("bounded scenario metadata required")
			}
		}
	}
	for _, surface := range def.Plan.Surfaces {
		if err := validateSurface(surface); err != nil {
			return err
		}
	}
	checkSelector := func(target model.Selector) error { return nil }
	var visitSelector func(model.Selector) error
	visitSelector = func(target model.Selector) error {
		if err := validateSurface(target.Surface); err != nil {
			return err
		}
		if target.Surface.TabID != "" || target.Surface.Title != "" {
			return errors.New("scenario cannot persist live tab or title identities")
		}
		for _, scope := range []map[string]model.Value{target.Scope.Window, target.Scope.Frame} {
			for _, value := range scope {
				if err := symbolicData(value, def.Plan.Inputs); err != nil {
					return errors.New("captured window/frame identity must be a declared input reference")
				}
			}
		}
		if target.Locator != nil {
			l := target.Locator
			if (l.Strategy == "name" || l.Strategy == "text" || l.Strategy == "label") && l.Value.Kind != model.ReferenceValue {
				return errors.New("captured target names/text must be declared inputs")
			}
			if l.Name != nil && l.Name.Kind != model.ReferenceValue {
				return errors.New("captured accessible names must be declared inputs")
			}
		}
		if target.Ancestor != nil {
			return visitSelector(*target.Ancestor)
		}
		return nil
	}
	checkSelector = visitSelector
	var checkPredicate func(*model.Predicate) error
	checkPredicate = func(pred *model.Predicate) error {
		if pred == nil {
			return nil
		}
		if pred.Scope.Target != nil {
			if err := checkSelector(*pred.Scope.Target); err != nil {
				return err
			}
		}
		for _, v := range pred.Inputs {
			if err := symbolicData(v, def.Plan.Inputs); err != nil {
				return err
			}
		}
		if pred.Matcher != nil && pred.Matcher.Expected != nil {
			return symbolicData(*pred.Matcher.Expected, def.Plan.Inputs)
		}
		return nil
	}
	for name := range def.Entity {
		if !ValidID(name) {
			return errors.New("bounded structural entity names required")
		}
	}
	for _, codes := range [][]string{def.Provenance.Gaps, def.Provenance.ReviewedGaps, def.Provenance.Issues} {
		for _, code := range codes {
			if !ValidID(code) {
				return errors.New("recording provenance persists structural codes, never captured text")
			}
		}
	}
	for _, v := range def.Entity {
		if err := symbolicData(v, def.Plan.Inputs); err != nil {
			return err
		}
	}
	for _, step := range def.Plan.Steps {
		if step.Command != "" {
			return errors.New("scenario requires typed IR without embedded command strings")
		}
		if err := checkSelector(step.Target); err != nil {
			return err
		}
		for name, v := range step.Arguments {
			if step.Action == "element.read" && name == "attribute" {
				continue
			}
			if err := symbolicData(v, def.Plan.Inputs); err != nil {
				return err
			}
		}
		for _, v := range step.Effect.BusinessKey {
			if err := symbolicData(v, def.Plan.Inputs); err != nil {
				return err
			}
		}
		for _, pred := range []*model.Predicate{step.Precondition, step.Postcondition, step.Effect.Reconcile} {
			if err := checkPredicate(pred); err != nil {
				return err
			}
		}
		if step.Assertion != nil && step.Assertion.Expected != nil {
			if err := symbolicData(*step.Assertion.Expected, def.Plan.Inputs); err != nil {
				return err
			}
		}
	}
	for _, binding := range def.Plan.Bindings {
		if binding.Selector != nil {
			if err := checkSelector(*binding.Selector); err != nil {
				return err
			}
		}
		if binding.Value != nil {
			if err := symbolicData(*binding.Value, def.Plan.Inputs); err != nil {
				return err
			}
		}
	}
	for _, artifact := range def.Plan.Artifacts {
		if err := symbolicData(artifact.FromPath, def.Plan.Inputs); err != nil {
			return err
		}
	}
	if err := checkPredicate(def.Plan.Objective); err != nil {
		return err
	}
	primaryPresent := false
	surfaces := PlanSurfaces(def.Plan)
	if len(surfaces) > 16 {
		return errors.New("scenario surface bound exceeded")
	}
	for _, surface := range surfaces {
		if surface == req.Surface {
			primaryPresent = true
		}
	}
	if !primaryPresent {
		return errors.New("declared primary environment surface is absent from the reusable plan")
	}
	// Every modeled reference is symbolic and resolved freshly. Captured runtime
	// values cannot hide in tagged object/array literals or run/artifact namespaces.
	return inspectValues(reflect.ValueOf(def.Plan))
}
func validateSurface(surface model.Surface) error {
	if surface.TabID != "" || surface.Title != "" {
		return errors.New("reusable scenario surface cannot contain live identity")
	}
	if surface.Kind == "web" {
		parsed, err := url.Parse(surface.Origin)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return errors.New("scenario web surface requires an exact origin without captured URL data")
		}
	}
	return (model.Selector{Surface: surface, Cardinality: "one"}).Validate()
}
func symbolicData(v model.Value, inputs map[string]model.InputDefinition) error {
	if v.Kind != model.ReferenceValue || !strings.HasPrefix(v.Ref, "input.") {
		return errors.New("captured business values must be declared input references")
	}
	name := strings.Split(v.Ref, ".")[1]
	if _, ok := inputs[name]; !ok {
		return fmt.Errorf("scenario input %s is undeclared", name)
	}
	return v.Validate()
}

var valueType = reflect.TypeOf(model.Value{})

func inspectValues(v reflect.Value) error {
	if !v.IsValid() {
		return nil
	}
	if v.Type() == valueType {
		value := v.Interface().(model.Value)
		if value.Kind == model.ObjectValue || value.Kind == model.ArrayValue {
			return errors.New("captured structured values cannot be persisted in reusable scenarios")
		}
		if value.Kind == model.ReferenceValue && !(strings.HasPrefix(value.Ref, "input.") || strings.HasPrefix(value.Ref, "binding.") || strings.HasPrefix(value.Ref, "step.")) {
			return errors.New("scenario cannot persist live run/artifact references")
		}
		return nil
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			return inspectValues(v.Elem())
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if err := inspectValues(v.Field(i)); err != nil {
				return err
			}
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			if err := inspectValues(iter.Value()); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if err := inspectValues(v.Index(i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// PlanSurfaces includes declarations and every nested target without runtime IDs.
func PlanSurfaces(plan model.Plan) []model.Surface {
	seen := map[model.Surface]bool{}
	add := func(surface model.Surface) { seen[surface] = true }
	var target func(*model.Selector)
	target = func(s *model.Selector) {
		if s == nil {
			return
		}
		add(s.Surface)
		target(s.Ancestor)
	}
	predicate := func(p *model.Predicate) {
		if p != nil {
			target(p.Scope.Target)
		}
	}
	for _, surface := range plan.Surfaces {
		add(surface)
	}
	for _, step := range plan.Steps {
		target(&step.Target)
		predicate(step.Precondition)
		predicate(step.Postcondition)
		predicate(step.Effect.Reconcile)
	}
	for _, binding := range plan.Bindings {
		target(binding.Selector)
	}
	predicate(plan.Objective)
	out := make([]model.Surface, 0, len(seen))
	for surface := range seen {
		out = append(out, surface)
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := json.Marshal(out[i])
		b, _ := json.Marshal(out[j])
		return string(a) < string(b)
	})
	return out
}
