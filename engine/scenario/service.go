// Package scenario composes private generated catalogue components and a pure
// selector. It proposes reusable immutable plans; Endly alone executes them.
package scenario

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data/scenariolist"
	"github.com/viant/mechanize/data/scenariopublish"
	"github.com/viant/mechanize/model"
	selector "github.com/viant/mechanize/scenario"
	"github.com/viant/xdatly/handler"
)

type Provenance = scenariopublish.Provenance
type Definition = scenariopublish.DraftDefinition

type Reference struct {
	ID            string `json:"id"`
	Revision      string `json:"revision"`
	ContentHash   string `json:"contentHash"`
	ObjectiveHash string `json:"objectiveHash"`
	SchemaVersion int    `json:"schemaVersion"`
}
type PublishDraftRequest struct {
	ID           string                 `json:"id"`
	Revision     string                 `json:"revision"`
	RecordingID  string                 `json:"recordingId"`
	Plan         model.Plan             `json:"plan"`
	Entity       map[string]model.Value `json:"entity"`
	Requirements selector.Requirements  `json:"requirements"`
	// These are review claims, never qualification or verified provenance.
	Reviewed     bool     `json:"reviewed"`
	Gaps         []string `json:"gaps,omitempty"`
	ReviewedGaps []string `json:"reviewedGaps,omitempty"`
}
type Summary struct {
	Surfaces     []model.Surface                  `json:"surfaces"`
	Reference    Reference                        `json:"reference"`
	State        string                           `json:"state"`
	Name         string                           `json:"name,omitempty"`
	Steps        int                              `json:"steps"`
	Inputs       map[string]model.InputDefinition `json:"inputs,omitempty"`
	Entity       map[string]model.Value           `json:"entity"`
	Requirements selector.Requirements            `json:"requirements"`
	Provenance   Provenance                       `json:"provenance"`
	Qualified    bool                             `json:"qualified"`
}
type PublishResult struct {
	PublicationConfirmed bool     `json:"publicationConfirmed"`
	Summary              Summary  `json:"summary"`
	NormalizedFields     []string `json:"normalizedFields,omitempty"`
}
type Cursor struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
}
type ListRequest struct {
	ObjectiveHash string  `json:"objectiveHash,omitempty"`
	After         *Cursor `json:"after,omitempty"`
	ID            string  `json:"id,omitempty"`
	Revision      string  `json:"revision,omitempty"`
	Limit         int     `json:"limit,omitempty"`
}
type ListResult struct {
	Next      *Cursor   `json:"next,omitempty"`
	Scenarios []Summary `json:"scenarios"`
	Truncated bool      `json:"truncated"`
}
type SelectRequest struct {
	ID            string                           `json:"id,omitempty"`
	Revision      string                           `json:"revision,omitempty"`
	ObjectiveHash string                           `json:"objectiveHash"`
	Entity        map[string]model.Value           `json:"entity"`
	InputSchema   map[string]model.InputDefinition `json:"inputSchema"`
	Inputs        map[string]model.Value           `json:"inputs"`
	Surface       model.Surface                    `json:"surface"`
}
type Environment struct {
	CoveredSurfaces []model.Surface
	Requirements    selector.Requirements
	ObservedAt      time.Time
	Verified        bool
}
type Selection struct {
	Status       string               `json:"status"`
	Reason       string               `json:"reason,omitempty"`
	Rejected     []selector.Rejection `json:"rejected,omitempty"`
	Reference    *Reference           `json:"reference,omitempty"`
	Plan         *model.Plan          `json:"plan,omitempty"`
	ProposalOnly bool                 `json:"proposalOnly"`
}
type Options struct {
	Invoke func(context.Context, auth.Principal, exec.ComponentRequest) (any, error)
	// Empty surface checks enrollment; exact surfaces also check operator ceilings.
	Authorize func(context.Context, auth.Principal, model.Surface) error
	// Callbacks are trusted configuration. Request fields cannot supply any of them.
	VerifyProvenance func(context.Context, auth.Principal, Definition) (Provenance, error)
	Environment      func(context.Context, auth.Principal, model.Surface) (Environment, error)
	Qualify          func(context.Context, auth.Principal, Reference, Environment) (selector.Cohort, error)
	Now              func() time.Time
	MaxAge           time.Duration
}
type Service struct{ options Options }

func New(options Options) (*Service, error) {
	if options.Invoke == nil || options.Authorize == nil {
		return nil, errors.New("private Datly invocation and verified enrollment/surface authorization required")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.MaxAge == 0 {
		options.MaxAge = 30 * time.Second
	}
	if options.MaxAge < time.Millisecond || options.MaxAge > time.Minute {
		return nil, errors.New("bounded fresh scenario environment required")
	}
	return &Service{options: options}, nil
}

var ErrRevisionConflict = errors.New("immutable scenario revision conflicts with canonical draft")

type PublicationError struct {
	Reference Reference
	Cause     error
}

func (e *PublicationError) Error() string { return "scenario draft publication failed or unknown" }
func (e *PublicationError) Unwrap() error { return e.Cause }
func (s *Service) bound(ctx context.Context, requested auth.Principal) (auth.Principal, error) {
	p, err := auth.FromContext(ctx)
	if err != nil || requested.Validate() != nil || p.Namespace != requested.Namespace {
		return auth.Principal{}, auth.ErrUnauthorized
	}
	if !p.HasScope("desktop:observe") && !p.HasScope("desktop:control") && !p.HasScope("desktop:read") {
		return auth.Principal{}, auth.ErrUnauthorized
	}
	if err = s.options.Authorize(ctx, p, model.Surface{}); err != nil {
		return auth.Principal{}, err
	}
	return p, ctx.Err()
}
func (s *Service) invoke(ctx context.Context, p auth.Principal, pkg, name, method string, input any, commit bool) (any, error) {
	var outcome handler.Outcome
	value, err := s.options.Invoke(ctx, p, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + pkg, Name: name}, Route: spec.RouteRef{Method: method, Path: "/internal/data/" + pkg}}, Input: input, Completion: func(v handler.Outcome) { outcome = v }})
	if err != nil {
		return nil, err
	}
	if commit && !outcome.CommitConfirmed() {
		return nil, errors.New("Datly scenario commit is not confirmed")
	}
	return value, nil
}
func (s *Service) read(ctx context.Context, p auth.Principal, id, revision string, limit int, cursor Cursor, objectiveHash string) ([]*scenariolist.ScenarioRevision, error) {
	if id == "" {
		id = "*"
	}
	if revision == "" {
		revision = "*"
	}
	input := &scenariolist.ListScenariosInput{}
	input.SetNamespace(p.Namespace)
	input.SetScenarioID(id)
	input.SetRevision(revision)
	input.SetLimit(limit)
	input.SetAfterID(cursor.ID)
	input.SetAfterRevision(cursor.Revision)
	if objectiveHash == "" {
		objectiveHash = "*"
	}
	input.SetObjectiveHash(objectiveHash)
	value, err := s.invoke(ctx, p, "scenariolist", "ListScenarios", "GET", input, false)
	if err != nil {
		return nil, err
	}
	output, ok := value.(*scenariolist.ListScenariosOutput)
	if !ok || output == nil || len(output.Data) > 101 {
		return nil, errors.New("bounded authorized scenario read unavailable")
	}
	for _, row := range output.Data {
		if row == nil || row.Namespace == nil || *row.Namespace != p.Namespace || row.ScenarioId == nil || row.Revision == nil || id != "*" && *row.ScenarioId != id || revision != "*" && *row.Revision != revision {
			return nil, auth.ErrUnauthorized
		}
	}
	if len(output.Data) > limit {
		output.Data = output.Data[:limit]
	}
	return output.Data, nil
}
func decode(row *scenariolist.ScenarioRevision) (Definition, Reference, error) {
	var zero Definition
	if row == nil || row.ScenarioId == nil || row.Revision == nil || row.ContentHash == nil || row.ObjectiveHash == nil || row.ContentJson == nil || row.PublicationState == nil || *row.PublicationState != "draft" {
		return zero, Reference{}, errors.New("incomplete persisted scenario")
	}
	def, err := scenariopublish.DecodeCanonical(*row.ContentJson)
	if err != nil {
		return zero, Reference{}, err
	}
	objective, err := scenariopublish.ObjectiveHash(def.Plan)
	if err != nil || def.ID != *row.ScenarioId || def.Revision != *row.Revision || scenariopublish.Digest([]byte(*row.ContentJson)) != *row.ContentHash || objective != *row.ObjectiveHash {
		return zero, Reference{}, errors.New("persisted scenario canonical identity/hash mismatch")
	}
	return def, Reference{ID: def.ID, Revision: def.Revision, ContentHash: *row.ContentHash, ObjectiveHash: objective, SchemaVersion: def.SchemaVersion}, nil
}
func summary(def Definition, ref Reference) Summary {
	return Summary{Surfaces: scenariopublish.PlanSurfaces(def.Plan), Reference: ref, State: "draft", Name: def.Plan.Name, Steps: len(def.Plan.Steps), Inputs: def.Plan.Inputs, Entity: def.Entity, Requirements: def.Requirements, Provenance: def.Provenance, Qualified: false}
}
func (s *Service) PublishDraft(ctx context.Context, requested auth.Principal, input PublishDraftRequest) (PublishResult, error) {
	p, err := s.bound(ctx, requested)
	if err != nil {
		return PublishResult{}, err
	}
	def := Definition{SchemaVersion: 1, ID: input.ID, Revision: input.Revision, Plan: input.Plan, Entity: input.Entity, Requirements: input.Requirements, Provenance: Provenance{RecordingID: input.RecordingID, Reviewed: false, Verified: false, Gaps: input.Gaps, Issues: []string{"provenanceUnverified"}}}
	def, normalized, err := normalize(def)
	if err != nil {
		return PublishResult{}, err
	}
	if err = s.authorizeDefinition(ctx, p, def); err != nil {
		return PublishResult{}, err
	}
	if s.options.VerifyProvenance != nil {
		claimed, cloneErr := cloneDefinition(def)
		if cloneErr != nil {
			return PublishResult{}, cloneErr
		}
		claimed.Provenance.Reviewed = input.Reviewed
		claimed.Provenance.ReviewedGaps = append([]string(nil), input.ReviewedGaps...)
		verified, verifyErr := s.options.VerifyProvenance(ctx, p, claimed)
		if verifyErr != nil {
			return PublishResult{}, verifyErr
		}
		if verified.RecordingID != input.RecordingID {
			return PublishResult{}, errors.New("trusted recording provenance identity differs")
		}
		def.Provenance = cloneProvenance(verified)
	}
	content, err := scenariopublish.Canonical(def)
	if err != nil {
		return PublishResult{}, err
	}
	objective, err := scenariopublish.ObjectiveHash(def.Plan)
	if err != nil {
		return PublishResult{}, err
	}
	ref := Reference{ID: def.ID, Revision: def.Revision, ContentHash: scenariopublish.Digest(content), ObjectiveHash: objective, SchemaVersion: 1}
	result := PublishResult{Summary: summary(def, ref), NormalizedFields: normalized}
	match := func() (bool, error) {
		rows, readErr := s.read(ctx, p, def.ID, def.Revision, 2, Cursor{ID: "*", Revision: "*"}, "")
		if readErr != nil {
			return false, readErr
		}
		if len(rows) == 0 {
			return false, nil
		}
		if len(rows) != 1 {
			return false, ErrRevisionConflict
		}
		_, stored, decodeErr := decode(rows[0])
		if decodeErr != nil {
			return false, decodeErr
		}
		if stored != ref || rows[0].ContentJson == nil || *rows[0].ContentJson != string(content) {
			return false, ErrRevisionConflict
		}
		return true, nil
	}
	exists, err := match()
	if err != nil || exists {
		result.PublicationConfirmed = exists && err == nil
		return result, err
	}
	row := &scenariopublish.ScenarioRevision{}
	row.SetNamespace(ptr(p.Namespace))
	row.SetScenarioId(ptr(def.ID))
	row.SetRevision(ptr(def.Revision))
	row.SetContentHash(ptr(ref.ContentHash))
	row.SetObjectiveHash(ptr(ref.ObjectiveHash))
	row.SetContentJson(ptr(string(content)))
	row.SetPublicationState(ptr("draft"))
	row.SetCreatedAt(ptr(s.options.Now().UTC().Format(time.RFC3339Nano)))
	writer := &scenariopublish.PublishScenarioDraftInput{}
	writer.SetNamespace(p.Namespace)
	writer.SetPublishScenarioDraft([]*scenariopublish.ScenarioRevision{row})
	if _, err = s.invoke(ctx, p, "scenariopublish", "PublishScenarioDraft", "POST", writer, true); err != nil {
		confirmed, readErr := match()
		if readErr == nil && confirmed {
			result.PublicationConfirmed = true
			return result, nil
		}
		return result, &PublicationError{Reference: ref, Cause: errors.Join(err, readErr)}
	}
	result.PublicationConfirmed = true
	return result, nil
}
func (s *Service) List(ctx context.Context, requested auth.Principal, input ListRequest) (ListResult, error) {
	p, err := s.bound(ctx, requested)
	if err != nil {
		return ListResult{}, err
	}
	if input.ID != "" && !scenariopublish.ValidID(input.ID) || input.Revision != "" && !scenariopublish.ValidID(input.Revision) {
		return ListResult{}, errors.New("exact bounded scenario identifiers required")
	}
	if input.ObjectiveHash != "" && len(input.ObjectiveHash) != 64 {
		return ListResult{}, errors.New("canonical objective hash required")
	}
	if input.Limit == 0 {
		input.Limit = 50
	}
	if input.Limit < 1 || input.Limit > 100 {
		return ListResult{}, errors.New("scenario list limit must be 1...100")
	}
	cursor := Cursor{ID: "*", Revision: "*"}
	if input.After != nil {
		if !scenariopublish.ValidID(input.After.ID) || !scenariopublish.ValidID(input.After.Revision) {
			return ListResult{}, errors.New("bounded exact scenario cursor required")
		}
		cursor = *input.After
	}
	rows, err := s.read(ctx, p, input.ID, input.Revision, input.Limit+1, cursor, input.ObjectiveHash)
	if err != nil {
		return ListResult{}, err
	}
	out := ListResult{Scenarios: []Summary{}, Truncated: len(rows) > input.Limit}
	if len(rows) > input.Limit {
		rows = rows[:input.Limit]
	}
	if out.Truncated && len(rows) > 0 {
		last := rows[len(rows)-1]
		out.Next = &Cursor{ID: *last.ScenarioId, Revision: *last.Revision}
	}
	for _, row := range rows {
		def, ref, err := decode(row)
		if err != nil {
			return ListResult{}, err
		}
		if s.authorizeDefinition(ctx, p, def) != nil {
			continue
		}
		out.Scenarios = append(out.Scenarios, summary(def, ref))
	}
	return out, nil
}
func (s *Service) Select(ctx context.Context, requested auth.Principal, input SelectRequest) (Selection, error) {
	attention := Selection{Status: "needsAttention", ProposalOnly: true}
	p, err := s.bound(ctx, requested)
	if err != nil {
		return attention, err
	}
	if err = s.options.Authorize(ctx, p, input.Surface); err != nil {
		return attention, err
	}
	if input.ID != "" && !scenariopublish.ValidID(input.ID) || input.Revision != "" && !scenariopublish.ValidID(input.Revision) {
		return attention, errors.New("exact bounded scenario identifiers required")
	}
	if len(input.ObjectiveHash) != 64 || len(input.Entity) == 0 || len(input.Entity) > 64 || len(input.InputSchema) > 128 || len(input.Inputs) > 128 {
		return attention, errors.New("bounded objective/entity/input selection required")
	}
	if s.options.Environment == nil {
		attention.Reason = "verified current environment is unavailable"
		return attention, nil
	}
	env, err := s.options.Environment(ctx, p, input.Surface)
	if err != nil {
		return attention, err
	}
	env = cloneEnvironment(env)
	now := s.options.Now()
	if !env.Verified || env.ObservedAt.IsZero() || env.ObservedAt.After(now) || now.Sub(env.ObservedAt) > s.options.MaxAge || env.Requirements.Surface != input.Surface {
		attention.Reason = "verified current environment is stale or differs from the requested surface"
		return attention, nil
	}
	rows, err := s.read(ctx, p, input.ID, input.Revision, 101, Cursor{ID: "*", Revision: "*"}, input.ObjectiveHash)
	if err != nil {
		return attention, err
	}
	if len(rows) > 100 {
		attention.Reason = "catalogue selection is truncated; request an exact scenario revision"
		return attention, nil
	}
	candidates := []selector.Candidate{}
	definitions := map[string]Definition{}
	references := map[string]Reference{}
	for _, row := range rows {
		def, ref, err := decode(row)
		if err != nil {
			return attention, err
		}
		if s.authorizeDefinition(ctx, p, def) != nil {
			continue
		}
		cohort := selector.Cohort{}
		// Stored review fields never establish authority. Reverify exact provenance
		// and obtain exact cohort evidence from configured trusted callbacks each time.
		if environmentCovers(env, def) && s.options.VerifyProvenance != nil && s.options.Qualify != nil && def.Provenance.Verified && def.Provenance.Reviewed && len(def.Provenance.Gaps) == 0 && len(def.Provenance.Issues) == 0 {
			detached, cloneErr := cloneDefinition(def)
			if cloneErr != nil {
				return attention, cloneErr
			}
			provenance, verifyErr := s.options.VerifyProvenance(ctx, p, detached)
			if verifyErr != nil {
				return attention, verifyErr
			}
			if reflect.DeepEqual(cloneProvenance(provenance), def.Provenance) {
				cohort, err = s.options.Qualify(ctx, p, ref, cloneEnvironment(env))
				if err != nil {
					return attention, err
				}
			}
		}
		entity := map[string]model.Value{}
		values := map[string]model.Value{}
		for k, v := range input.Inputs {
			values["input."+k] = v
		}
		for name, value := range def.Entity {
			resolved, resolveErr := model.ResolveValue(value, values)
			if resolveErr != nil {
				entity = nil
				break
			}
			entity[name] = resolved
		}
		c := selector.Candidate{Namespace: p.Namespace, ID: def.ID, Revision: def.Revision, ObjectiveHash: ref.ObjectiveHash, Entity: entity, Inputs: def.Plan.Inputs, Requirements: def.Requirements, Qualified: cohort, ObservedAt: env.ObservedAt, ExactConstraints: exactConstraints(def)}
		candidates = append(candidates, c)
		key := def.ID + "/" + def.Revision
		definitions[key] = def
		references[key] = ref
	}
	selected, err := selector.Select(ctx, selector.Request{ObjectiveHash: input.ObjectiveHash, Entity: input.Entity, InputSchema: input.InputSchema, Inputs: input.Inputs, Environment: env.Requirements, Now: now, MaxAge: s.options.MaxAge}, candidates)
	if err != nil {
		return attention, err
	}
	out := Selection{Status: selected.Status, Reason: selected.Reason, Rejected: selected.Rejected, ProposalOnly: true}
	if selected.Candidate != nil {
		key := selected.Candidate.ID + "/" + selected.Candidate.Revision
		def := definitions[key]
		ref := references[key]
		out.Reference = &ref
		out.Plan = &def.Plan
	}
	return out, nil
}
func exactConstraints(def Definition) []string {
	out := []string{"objective", "surface", "profile", "version", "verification", "cohort"}
	for name := range def.Entity {
		out = append(out, "entity:"+name)
	}
	for name := range def.Plan.Inputs {
		out = append(out, "input:"+name)
	}
	sort.Strings(out)
	return out
}
func ptr[T any](v T) *T { return &v }

var surfaceType = reflect.TypeOf(model.Surface{})

func normalize(def Definition) (Definition, []string, error) {
	content, err := json.Marshal(def)
	if err != nil {
		return Definition{}, nil, err
	}
	if len(content) > scenariopublish.MaximumDraftBytes {
		return Definition{}, nil, errors.New("scenario draft byte bound exceeded")
	}
	var copy Definition
	if err = json.Unmarshal(content, &copy); err != nil {
		return Definition{}, nil, err
	}
	paths := []string{}
	var visit func(reflect.Value, string) error
	visit = func(v reflect.Value, path string) error {
		if !v.IsValid() {
			return nil
		}
		if v.Type() == surfaceType {
			surface := v.Interface().(model.Surface)
			if surface.Title != "" {
				return errors.New("captured title identity cannot be reused; explicitly remove it before publication")
			}
			if surface.TabID != "" {
				if surface.Kind != "web" || surface.Origin == "" {
					return errors.New("live tab requires an explicit stable origin for reusable normalization")
				}
				surface.TabID = ""
				v.Set(reflect.ValueOf(surface))
				paths = append(paths, path+".tabId")
			}
			return nil
		}
		switch v.Kind() {
		case reflect.Pointer:
			if !v.IsNil() {
				return visit(v.Elem(), path)
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if err := visit(v.Field(i), path+"."+v.Type().Field(i).Name); err != nil {
					return err
				}
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				if err := visit(v.Index(i), fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		case reflect.Map:
			for _, key := range v.MapKeys() {
				value := v.MapIndex(key)
				settable := reflect.New(value.Type()).Elem()
				settable.Set(value)
				if err := visit(settable, path+"["+fmt.Sprint(key.Interface())+"]"); err != nil {
					return err
				}
				v.SetMapIndex(key, settable)
			}
		}
		return nil
	}
	if err = visit(reflect.ValueOf(&copy).Elem(), "definition"); err != nil {
		return Definition{}, nil, err
	}
	sort.Strings(paths)
	return copy, paths, nil
}

func cloneDefinition(def Definition) (Definition, error) {
	var copy Definition
	content, err := json.Marshal(def)
	if err != nil {
		return copy, err
	}
	err = json.Unmarshal(content, &copy)
	return copy, err
}
func cloneProvenance(p Provenance) Provenance {
	p.Gaps = append([]string(nil), p.Gaps...)
	p.ReviewedGaps = append([]string(nil), p.ReviewedGaps...)
	p.Issues = append([]string(nil), p.Issues...)
	return p
}
func cloneEnvironment(e Environment) Environment {
	e.CoveredSurfaces = append([]model.Surface(nil), e.CoveredSurfaces...)
	e.Requirements.Capabilities = append([]string(nil), e.Requirements.Capabilities...)
	e.Requirements.Permissions = append([]string(nil), e.Requirements.Permissions...)
	return e
}

func (s *Service) authorizeDefinition(ctx context.Context, p auth.Principal, def Definition) error {
	if err := s.options.Authorize(ctx, p, def.Requirements.Surface); err != nil {
		return err
	}
	for _, surface := range scenariopublish.PlanSurfaces(def.Plan) {
		if surface == def.Requirements.Surface {
			continue
		}
		if err := s.options.Authorize(ctx, p, surface); err != nil {
			return err
		}
	}
	return nil
}
func environmentCovers(env Environment, def Definition) bool {
	for _, required := range scenariopublish.PlanSurfaces(def.Plan) {
		if required == env.Requirements.Surface {
			continue
		}
		found := false
		for _, covered := range env.CoveredSurfaces {
			if required == covered {
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
