package objective

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

// NativeEvidence is a fresh read receipt from an authenticated native helper.
// The host must bind the read to the verified user's consent, exact selector and
// positive value-read policy. A dispatch receipt cannot supply this evidence.
type NativeEvidence struct {
	HelperEpoch string
	TargetRef   string
	ObservedAt  time.Time
}
type NativeRead func(context.Context, auth.Principal, model.Selector, string) (model.Value, NativeEvidence, error)
type NativeMatch func(context.Context, auth.Principal, model.Selector, string) (bool, NativeEvidence, error)
type NativeAdapter struct {
	read    NativeRead
	matches NativeMatch
}

// NewNativeWithMatcher adds a boolean-only comparison for authorized plaintext
// targets. Ordinary value reads retain their separate identifier policy.
func NewNativeWithMatcher(read NativeRead, matches NativeMatch) (*NativeAdapter, error) {
	a, err := NewNative(read)
	if err != nil {
		return nil, err
	}
	if matches == nil {
		return nil, errors.New("qualified native comparison callback required")
	}
	a.matches = matches
	return a, nil
}

func NewNative(read NativeRead) (*NativeAdapter, error) {
	if read == nil {
		return nil, errors.New("qualified native read callback required")
	}
	return &NativeAdapter{read: read}, nil
}
func (a *NativeAdapter) Enrollment() Enrollment {
	predicates := map[string]bool{"valueEquals": true}
	if a != nil && a.matches != nil {
		predicates["literalValueMatches"] = true
	}
	return Enrollment{Adapter: a, MaximumAuthority: Observational, AllowedPredicates: predicates}
}
func boundedNativeString(value model.Value, maximum int, empty bool) (string, error) {
	if value.Kind != model.StringValue || value.Validate() != nil || len(value.String) > maximum || (!empty && strings.TrimSpace(value.String) == "") || strings.ContainsRune(value.String, 0) {
		return "", errors.New("bounded typed native string required")
	}
	return value.String, nil
}
func nativeEvidenceID(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Evaluate implements only native.valueEquals. All inputs are typed selectors;
// this adapter cannot execute scripts, dispatch actions, or read clipboard text.
type observationWaitKey struct{}

// WithObservationWait requests read-only settling for an action postcondition.
// It grants no scope, consent or input authority. A deadline is also required;
// snapshot/precondition evaluations and direct unbounded calls stay one-shot.
func WithObservationWait(ctx context.Context) context.Context {
	return context.WithValue(ctx, observationWaitKey{}, true)
}

func (a *NativeAdapter) Evaluate(ctx context.Context, p auth.Principal, name string, inputs map[string]model.Value) (Result, error) {
	enabled, _ := ctx.Value(observationWaitKey{}).(bool)
	if _, bounded := ctx.Deadline(); !enabled || !bounded {
		return a.evaluateOnce(ctx, p, name, inputs)
	}
	return waitNativeObservation(ctx, 50*time.Millisecond, 601, func() (Result, error) { return a.evaluateOnce(ctx, p, name, inputs) })
}
func transientNativeObservation(err error) bool {
	var detail *model.MechanizeError
	if !errors.As(err, &detail) || detail.Stage != "native" {
		return false
	}
	switch detail.Code {
	case "incompleteObservation", "targetNotFound", "attributeUnavailable":
		return true
	}
	return false
}
func waitNativeObservation(ctx context.Context, interval time.Duration, maximum int, read func() (Result, error)) (Result, error) {
	for attempt := 0; attempt < maximum; attempt++ {
		if err := ctx.Err(); err != nil {
			return Result{Truth: Unknown, Authority: Observational}, err
		}
		result, err := read()
		if canceled := ctx.Err(); canceled != nil {
			return Result{Truth: Unknown, Authority: Observational}, canceled
		}
		if err == nil && result.Truth != False {
			return result, nil
		}
		if err != nil && !transientNativeObservation(err) {
			return result, err
		}
		if attempt+1 == maximum {
			return Result{Truth: Unknown, Authority: Observational, Reason: "native observation attempt limit reached"}, errors.New("native observation attempt limit reached")
		}
		timer := time.NewTimer(interval)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return Result{Truth: Unknown, Authority: Observational}, ctx.Err()
		}
	}
	return Result{Truth: Unknown, Authority: Observational}, errors.New("native observation attempt limit reached")
}
func (a *NativeAdapter) evaluateOnce(ctx context.Context, p auth.Principal, name string, inputs map[string]model.Value) (Result, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
		return Result{}, auth.ErrUnauthorized
	}
	if a == nil || a.read == nil || (name != "valueEquals" && (name != "literalValueMatches" || a.matches == nil)) {
		return Result{}, errors.New("qualified native.valueEquals predicate required")
	}
	for key := range inputs {
		switch key {
		case "bundleID", "processId", "processStartToken", "strategy", "selector", "name", "nativeRoot", "windowTitle", "windowRole", "ancestorID", "attribute", "expected":
		default:
			return Result{}, errors.New("unsupported native predicate input")
		}
	}
	bundle, err := boundedNativeString(inputs["bundleID"], 256, false)
	if err != nil {
		return Result{}, err
	}
	for _, r := range bundle {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_') {
			return Result{}, errors.New("exact native bundle identifier required")
		}
	}
	strategy, err := boundedNativeString(inputs["strategy"], 16, false)
	if err != nil {
		return Result{}, err
	}
	if strategy != "id" && strategy != "name" && strategy != "role" {
		return Result{}, errors.New("unsupported native selector strategy")
	}
	selectorValue, err := boundedNativeString(inputs["selector"], 512, false)
	if err != nil {
		return Result{}, err
	}
	attribute, err := boundedNativeString(inputs["attribute"], 16, false)
	if err != nil {
		return Result{}, err
	}
	switch attribute {
	case "value", "name", "identifier", "role", "staticText", "focused", "enabled":
	default:
		return Result{}, errors.New("unsupported native observation attribute")
	}
	expected := ""
	booleanAttribute := attribute == "focused" || attribute == "enabled"
	if booleanAttribute {
		if inputs["expected"].Kind != model.BoolValue || inputs["expected"].Validate() != nil {
			return Result{}, errors.New("native boolean comparison requires typed boolean expectation")
		}
	} else {
		expected, err = boundedNativeString(inputs["expected"], 4096, true)
		if err != nil {
			return Result{}, err
		}
	}
	surface := model.Surface{Kind: "native", BundleID: bundle}
	pid, hasPID := inputs["processId"]
	token, hasToken := inputs["processStartToken"]
	if hasPID != hasToken {
		return Result{}, errors.New("native predicate process identity requires both PID and start token")
	}
	if hasPID {
		if pid.Kind != model.NumberValue || pid.Validate() != nil || pid.Number <= 0 || pid.Number > 2147483647 {
			return Result{}, errors.New("native predicate requires a positive typed process PID")
		}
		start, err := boundedNativeString(token, 27, false)
		if err != nil || !model.ValidProcessStartToken(start) {
			return Result{}, errors.New("native predicate requires a canonical process start token")
		}
		surface.ProcessID = int(pid.Number)
		surface.ProcessStartToken = start
		if err := surface.ValidateProcessIdentity(); err != nil {
			return Result{}, err
		}
	}
	target := model.Selector{Surface: surface, Locator: &model.Locator{Strategy: strategy, Value: model.Value{Kind: model.StringValue, String: selectorValue}, Exact: true}, Cardinality: "one"}
	if value, exists := inputs["name"]; exists {
		roleName, err := boundedNativeString(value, 512, false)
		if err != nil || strategy != "role" {
			return Result{}, errors.New("role name requires a bounded role selector")
		}
		target.Locator.Name = &model.Value{Kind: model.StringValue, String: roleName}
	}
	if value, exists := inputs["nativeRoot"]; exists {
		root, err := boundedNativeString(value, 16, false)
		_, windowTitle := inputs["windowTitle"]
		_, windowRole := inputs["windowRole"]
		if err != nil || (root != "menuBar" && root != "focusedElement") || windowTitle || windowRole {
			return Result{}, errors.New("native root requires menuBar or focusedElement without window inputs")
		}
		target.Scope.NativeRoot = root
	}
	if value, exists := inputs["windowTitle"]; exists {
		window, err := boundedNativeString(value, 512, false)
		if err != nil {
			return Result{}, err
		}
		target.Scope.Window = map[string]model.Value{"title": {Kind: model.StringValue, String: window}}
	}
	if value, exists := inputs["windowRole"]; exists {
		windowRole, err := boundedNativeString(value, 32, false)
		if err != nil || target.Scope.Window == nil || (windowRole != "window" && windowRole != "AXWindow") {
			return Result{}, errors.New("window role requires an exact window title and window/AXWindow role")
		}
		target.Scope.Window["role"] = model.Value{Kind: model.StringValue, String: windowRole}
	}
	if err = target.Validate(); err != nil {
		return Result{}, err
	}
	if value, exists := inputs["ancestorID"]; exists {
		ancestorID, err := boundedNativeString(value, 512, false)
		if err != nil {
			return Result{}, err
		}
		target.Ancestor = &model.Selector{Surface: target.Surface, Scope: target.Scope,
			Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: ancestorID}, Exact: true}, Cardinality: "one"}
		if err = target.Validate(); err != nil {
			return Result{}, err
		}
	}
	if name == "literalValueMatches" {
		if !p.HasScope("desktop:control") || target.Surface.ProcessID <= 0 || attribute != "value" {
			return Result{}, errors.New("literal comparison requires control identity, exact native process and value attribute")
		}
		matches, evidence, err := a.matches(ctx, p, target, expected)
		if err != nil {
			return Result{}, err
		}
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if !nativeEvidenceID(evidence.HelperEpoch) || !nativeEvidenceID(evidence.TargetRef) || evidence.ObservedAt.IsZero() {
			return Result{Truth: Unknown, Authority: Observational, Reason: "native comparison evidence is incomplete"}, nil
		}
		reference, _ := json.Marshal(struct {
			HelperEpoch string `json:"helperEpoch"`
			TargetRef   string `json:"targetRef"`
		}{evidence.HelperEpoch, evidence.TargetRef})
		truth := False
		if matches {
			truth = True
		}
		return Result{Truth: truth, Authority: Observational, ObservedAt: evidence.ObservedAt, Evidence: []Evidence{{Kind: "nativeLiteralComparison", Reference: string(reference)}}}, nil
	}
	value, evidence, err := a.read(ctx, p, target, attribute)
	if err != nil {
		return Result{}, err
	}
	if err = ctx.Err(); err != nil {
		return Result{}, err
	}
	observed := ""
	if booleanAttribute {
		if value.Kind != model.BoolValue || value.Validate() != nil {
			err = errors.New("boolean native evidence required")
		}
	} else {
		observed, err = boundedNativeString(value, 4096, true)
	}
	if err != nil || !nativeEvidenceID(evidence.HelperEpoch) || !nativeEvidenceID(evidence.TargetRef) || evidence.ObservedAt.IsZero() {
		return Result{Truth: Unknown, Authority: Observational, Reason: "native read evidence is incomplete"}, nil
	}
	reference, _ := json.Marshal(struct {
		HelperEpoch string `json:"helperEpoch"`
		TargetRef   string `json:"targetRef"`
	}{evidence.HelperEpoch, evidence.TargetRef})
	truth := False
	if booleanAttribute && value.Bool == inputs["expected"].Bool || !booleanAttribute && observed == expected {
		truth = True
	}
	return Result{Truth: truth, Authority: Observational, ObservedAt: evidence.ObservedAt, Evidence: []Evidence{{Kind: "nativeUIRead", Reference: string(reference)}}}, nil
}
