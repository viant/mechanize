// Package record compiles redacted semantic demonstrations into reviewable IR.
package record

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"

	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/model"
)

type Request struct {
	Name        string                             `json:"name"`
	Surface     model.Surface                      `json:"surface"`
	Objective   *model.Predicate                   `json:"objective,omitempty"`
	Inputs      map[string]model.InputDefinition   `json:"inputs,omitempty"`
	Parameters  map[uint64]string                  `json:"parameters,omitempty"`
	Checkpoints map[uint64]*model.CheckpointPolicy `json:"checkpoints,omitempty"`
	Reviewed    bool                               `json:"reviewed"`
}
type Issue struct {
	Sequence uint64 `json:"sequence,omitempty"`
	Code     string `json:"code"`
}
type Provenance struct {
	StepID         string          `json:"stepId,omitempty"`
	Sequences      []uint64        `json:"sequences"`
	Source         string          `json:"source"`
	Confidence     string          `json:"confidence"`
	EventSurface   string          `json:"eventSurface,omitempty"`
	CapturedKind   string          `json:"capturedKind,omitempty"`
	Lineages       []string        `json:"lineages,omitempty"`
	NativeIdentity *NativeIdentity `json:"nativeIdentity,omitempty"`
	NativeTarget   *NativeTarget   `json:"target,omitempty"`
}
type Report struct {
	Qualification   string       `json:"qualification"`
	Reviewed        bool         `json:"reviewed"`
	ProductionReady bool         `json:"productionReady"`
	BusinessSuccess bool         `json:"businessSuccess"`
	Gaps            []RecordGap  `json:"gaps,omitempty"`
	Issues          []Issue      `json:"issues,omitempty"`
	ReviewIssues    []Issue      `json:"reviewIssues,omitempty"`
	Provenance      []Provenance `json:"provenance"`
	CapturedActions int          `json:"capturedActions"`
	CompiledSteps   int          `json:"compiledSteps"`
}
type DraftAction struct {
	Sequence          uint64                  `json:"sequence"`
	CapturedKind      string                  `json:"capturedKind"`
	ProposedAction    string                  `json:"proposedAction,omitempty"`
	Surface           *model.Surface          `json:"surface,omitempty"`
	NativeIdentity    *NativeIdentity         `json:"nativeIdentity,omitempty"`
	NativeTarget      *NativeTarget           `json:"target,omitempty"`
	Locator           *chrome.Locator         `json:"locator,omitempty"`
	ParameterRequired bool                    `json:"parameterRequired"`
	InputRef          *model.Value            `json:"inputRef,omitempty"`
	Checkpoint        *model.CheckpointPolicy `json:"checkpoint,omitempty"`
	Lineage           string                  `json:"lineage"`
	Source            string                  `json:"source"`
	Qualification     string                  `json:"qualification"`
	ReviewIssues      []Issue                 `json:"reviewIssues,omitempty"`
}
type Export struct {
	Plan         model.Plan    `json:"plan"`
	Report       Report        `json:"report"`
	DraftActions []DraftAction `json:"draftActions,omitempty"`
}

type Compiler struct{}

// Normalize accepts common events and the checked legacy Chrome boundary. It
// preserves semantic sequence and identity while discarding all captured text.
func (Compiler) Normalize(input any) ([]RecordEvent, error) {
	var events []RecordEvent
	switch old := input.(type) {
	case nil:
	case []RecordEvent:
		events = old
	case []chrome.RecordEvent:
		id := ""
		if len(old) > 0 {
			id = old[0].RecordingID
		}
		converted, err := FromChromeBatch(chrome.RecordBatch{RecordingID: id, Events: old})
		if err != nil {
			return nil, err
		}
		events = converted.Events
	default:
		return nil, fmt.Errorf("unsupported recording event envelope")
	}
	if len(events) > 10000 {
		return nil, fmt.Errorf("recording compiler event bound exceeded")
	}
	result := make([]RecordEvent, 0, len(events))
	var previous uint64
	for _, event := range events {
		if event.Sequence <= previous {
			return nil, fmt.Errorf("non-monotonic recording sequence")
		}
		previous = event.Sequence
		if err := event.Validate(); err != nil {
			return nil, err
		}
		event.Value = nil
		result = append(result, event)
	}
	return result, nil
}
func eventSurface(event RecordEvent) (model.Surface, bool) {
	if event.EventSurface == "native" && event.NativeIdentity != nil {
		return model.Surface{Kind: "native", BundleID: event.NativeIdentity.BundleID}, true
	}
	if event.EventSurface == "web" && event.Identity != nil && event.Origin != "" {
		return model.Surface{Kind: "web", Origin: event.Origin, TabID: event.Identity.ProfileChannel + "/" + event.Identity.BrowserInstance + "/" + strconv.Itoa(event.Identity.TabID)}, true
	}
	return model.Surface{}, false
}
func issue(out *Export, event RecordEvent, code string) {
	out.Report.Issues = append(out.Report.Issues, Issue{Sequence: event.Sequence, Code: code})
}
func provenance(event RecordEvent, step string) Provenance {
	return Provenance{StepID: step, Sequences: []uint64{event.Sequence}, Source: event.Source, Confidence: event.SelectorConfidence, EventSurface: event.EventSurface, CapturedKind: event.Kind, Lineages: []string{event.Lineage}, NativeIdentity: event.NativeIdentity, NativeTarget: event.NativeTarget}
}

func (c Compiler) Compile(req Request, input any, gaps []RecordGap) (Export, error) {
	if req.Surface.Kind != "desktop" && req.Surface.Kind != "native" && req.Surface.Kind != "web" {
		return Export{}, fmt.Errorf("explicit desktop/native/web recording collection required")
	}
	if req.Surface.Kind == "desktop" && (req.Surface.BundleID != "" || req.Surface.Origin != "" || req.Surface.Title != "" || req.Surface.TabID != "") {
		return Export{}, fmt.Errorf("desktop collection cannot carry per-app or web facts")
	}
	if req.Surface.Kind == "web" && (req.Surface.Origin == "" || req.Surface.TabID == "") {
		return Export{}, fmt.Errorf("exact web recording collection required")
	}
	if req.Surface.Kind == "native" && req.Surface.BundleID == "" {
		return Export{}, fmt.Errorf("exact native recording collection required")
	}
	if len(req.Inputs) > 128 {
		return Export{}, fmt.Errorf("recording compiler input bound exceeded")
	}
	for _, definition := range req.Inputs {
		if definition.Default != nil {
			return Export{}, fmt.Errorf("recorded export inputs cannot carry default values")
		}
	}
	events, err := c.Normalize(input)
	if err != nil {
		return Export{}, err
	}
	out := Export{Plan: model.Plan{SchemaVersion: 1, Name: req.Name, Inputs: map[string]model.InputDefinition{}, Surfaces: map[string]model.Surface{}, Objective: req.Objective}, Report: Report{Qualification: "unqualified", Reviewed: req.Reviewed, Gaps: append([]RecordGap(nil), gaps...)}}
	for name, definition := range req.Inputs {
		out.Plan.Inputs[name] = definition
	}
	if req.Surface.Kind != "desktop" {
		out.Plan.Surfaces["recorded"] = req.Surface
	}
	// Declare concrete operation targets, never a wildcard or frozen enrollment
	// ceiling. Desktop collection can retain new app and browser surface lineage.
	for _, event := range events {
		if surface, ok := eventSurface(event); ok {
			exists := false
			for _, declared := range out.Plan.Surfaces {
				if declared == surface {
					exists = true
					break
				}
			}
			if !exists {
				name := "recorded"
				if len(out.Plan.Surfaces) > 0 {
					name = fmt.Sprintf("recorded_%d", len(out.Plan.Surfaces)+1)
				}
				out.Plan.Surfaces[name] = surface
			}
		}
	}
	if !req.Reviewed {
		out.Report.Issues = append(out.Report.Issues, Issue{Code: "operatorReviewRequired"})
	}
	if req.Objective == nil {
		out.Report.Issues = append(out.Report.Issues, Issue{Code: "objectiveRequired"})
	} else {
		if err = req.Objective.Validate(); err != nil {
			return Export{}, err
		}
		if req.Objective.Kind == "adapter" {
			out.Plan.Requires = &model.Requirements{Adapters: []string{req.Objective.Adapter}}
		}
	}
	var last uint64
	for _, event := range events {
		if event.Sequence != last+1 {
			issue(&out, event, "sequenceGap")
		}
		last = event.Sequence
		if event.Kind == "start" || event.Kind == "stop" {
			continue
		}
		if event.Kind == "pause" || event.Kind == "gap" {
			issue(&out, event, "coverageGap")
			out.Report.Provenance = append(out.Report.Provenance, provenance(event, ""))
			continue
		}
		out.Report.CapturedActions++
		draft := DraftAction{Sequence: event.Sequence, CapturedKind: event.Kind, NativeIdentity: event.NativeIdentity, NativeTarget: event.NativeTarget, Locator: event.Locator, ParameterRequired: event.ParameterRequired || event.Kind == "fill" || event.Kind == "select", Checkpoint: req.Checkpoints[event.Sequence], Lineage: event.Lineage, Source: event.Source, Qualification: "unqualified"}
		if surface, ok := eventSurface(event); ok {
			draft.Surface = &surface
		}
		switch event.Kind {
		case "press":
			draft.ProposedAction = "element.press"
		case "fill":
			draft.ProposedAction = "element.fill"
		case "select":
			draft.ProposedAction = "element.select"
		case "submit":
			draft.ProposedAction = "element.submit"
		case "app.open":
			draft.ProposedAction = "app.open"
		case "app.activate":
			if event.EventSurface == "native" && event.Trusted && event.SourceAttested && req.Reviewed {
				draft.ProposedAction = "app.activate"
			}
		}
		if draft.ParameterRequired {
			name := req.Parameters[event.Sequence]
			definition, exists := out.Plan.Inputs[name]
			if !exists || definition.Type != model.StringValue {
				name = fmt.Sprintf("recorded_%d", event.Sequence)
				out.Plan.Inputs[name] = model.InputDefinition{Type: model.StringValue, Required: true, Sensitive: event.Redacted}
				issue(&out, event, "unresolvedInput")
			}
			ref := model.Value{Kind: model.ReferenceValue, Expected: model.StringValue, Ref: "input." + name}
			draft.InputRef = &ref
		}
		out.DraftActions = append(out.DraftActions, draft)
		unresolved := func(code string) {
			issue(&out, event, code)
			out.Report.Provenance = append(out.Report.Provenance, provenance(event, ""))
		}
		action := ""
		switch event.Kind {
		case "press":
			action = "element.press"
		case "fill":
			action = "element.fill"
		case "select":
			action = "element.select"
		case "submit":
			action = "element.submit"
		case "app.open":
			action = "app.open"
		case "app.activate":
			if event.EventSurface != "native" || !event.Trusted || !event.SourceAttested || !req.Reviewed {
				unresolved("appActivationSemanticsUnqualified")
				continue
			}
			action = "app.activate"
		default:
			unresolved("unsupportedAction")
			continue
		}
		surface, ok := eventSurface(event)
		if !ok {
			unresolved("unresolvedIdentity")
			continue
		}
		if req.Surface.Kind != "desktop" && surface != req.Surface {
			unresolved("recordingScopeMismatch")
			continue
		}
		if !event.SourceAttested {
			issue(&out, event, "sourceNotAttested")
		}
		if event.EventSurface == "native" && (!event.Trusted || !event.SourceAttested || !req.Reviewed) {
			unresolved("nativeProvenanceReviewRequired")
			continue
		}
		if event.EventSurface == "web" && !event.Trusted {
			unresolved("unresolvedTarget")
			continue
		}
		var locator *model.Locator
		if action != "app.open" && action != "app.activate" {
			if event.Locator == nil {
				unresolved("unresolvedTarget")
				continue
			}
			if event.EventSurface == "native" {
				target := event.NativeTarget
				if target == nil || target.Role == "" || target.Identifier == "" || !target.IdentifierQualified || target.IdentifierDigest != "" || event.Locator.Strategy != "id" || event.Locator.Value != target.Identifier || !event.Locator.Exact {
					unresolved("nativeLocatorUnqualified")
					continue
				}
			}
			locator = &model.Locator{Strategy: event.Locator.Strategy, Value: model.Value{Kind: model.StringValue, String: event.Locator.Value}, Exact: event.Locator.Exact}
			if event.Locator.Name != nil {
				locator.Name = &model.Value{Kind: model.StringValue, String: *event.Locator.Name}
			}
		} else if event.EventSurface != "native" || !event.Trusted || !event.SourceAttested || !req.Reviewed {
			unresolved("appLaunchSemanticsUnqualified")
			continue
		}
		target := model.Selector{Surface: surface, Locator: locator, Cardinality: "one"}
		if err := target.Validate(); err != nil {
			unresolved("unsupportedLocator")
			continue
		}
		if event.RecordingID == "" || event.Sequence == 0 || event.Sequence > uint64(1<<63-1) {
			unresolved("recordingIdentityUnavailable")
			continue
		}
		step := model.Step{ID: fmt.Sprintf("recorded_%d", event.Sequence), Action: action, Target: target, TimeoutMs: 5000, Arguments: map[string]model.Value{}, Effect: model.Effect{Class: model.ExternalNonIdempotent}, Checkpoint: req.Checkpoints[event.Sequence]}
		// This identifies the source action without copying captured values.
		// effectReviewRequired remains: provenance is not a business-entity oracle.
		step.Effect.BusinessKey = map[string]model.Value{"recording": {Kind: model.StringValue, String: event.RecordingID}, "sequence": {Kind: model.NumberValue, Number: int64(event.Sequence)}}
		if action == "element.fill" || action == "element.select" {
			step.Arguments["value"] = *draft.InputRef
		}
		if event.Redacted || event.ValueTruncated {
			issue(&out, event, "redactedOrTruncatedInput")
		}
		if event.SelectorConfidence != "high" {
			issue(&out, event, "targetReviewRequired")
		}
		issue(&out, event, "effectReviewRequired")
		if event.Kind == "fill" && step.Checkpoint == nil && len(out.Plan.Steps) > 0 && len(out.Report.Provenance) > 0 {
			previous := out.Plan.Steps[len(out.Plan.Steps)-1]
			origin := &out.Report.Provenance[len(out.Report.Provenance)-1]
			if origin.StepID == previous.ID && previous.Checkpoint == nil && origin.Sequences[len(origin.Sequences)-1]+1 == event.Sequence && reflect.DeepEqual(previous.Target, step.Target) && reflect.DeepEqual(origin.NativeIdentity, event.NativeIdentity) {
				out.Plan.Steps[len(out.Plan.Steps)-1].Arguments = step.Arguments
				origin.Sequences = append(origin.Sequences, event.Sequence)
				origin.Lineages = append(origin.Lineages, event.Lineage)
				continue
			}
		}
		out.Plan.Steps = append(out.Plan.Steps, step)
		out.Report.Provenance = append(out.Report.Provenance, provenance(event, step.ID))
	}
	out.Report.CompiledSteps = len(out.Plan.Steps)
	sort.SliceStable(out.Report.Issues, func(i, j int) bool { return out.Report.Issues[i].Sequence < out.Report.Issues[j].Sequence })
	out.Report.ReviewIssues = append([]Issue(nil), out.Report.Issues...)
	for index := range out.DraftActions {
		draft := &out.DraftActions[index]
		for _, problem := range out.Report.Issues {
			if problem.Sequence == 0 || problem.Sequence == draft.Sequence {
				draft.ReviewIssues = append(draft.ReviewIssues, problem)
			}
		}
	}
	if err = c.Validate(out); err != nil {
		return Export{}, err
	}
	return out, nil
}
func (Compiler) Validate(out Export) error { return out.Plan.Validate() }
