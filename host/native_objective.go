package host

import (
	"context"
	"errors"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
)

// nativePredicateError bridges helper errors only at the read-only objective
// boundary. Transport failures never qualify for observational settling.
func nativePredicateError(err error) error {
	var transport *native.TransportError
	if errors.As(err, &transport) {
		return err
	}
	var helper *native.NativeError
	if !errors.As(err, &helper) || helper == nil || helper.Stage != "native" || helper.DispatchState != "notDispatched" {
		return err
	}
	switch helper.Code {
	case "incompleteObservation", "targetNotFound", "attributeUnavailable":
		return errors.Join(err, &model.MechanizeError{Code: helper.Code, Message: helper.Message, Stage: helper.Stage, RetryableRead: helper.RetryableRead, DispatchState: helper.DispatchState})
	default:
		return err
	}
}

func (h *Host) nativeObjective(c Config) (*objective.Evaluator, error) {
	enrolled := map[string]objective.Enrollment{}
	if c.NativeLaunch != nil && c.NativeLaunch.Mode == "semantic" {
		adapter, err := objective.NewNativeWithMatcher(h.readNativePredicate, h.matchNativeLiteral)
		if err != nil {
			return nil, err
		}
		enrolled["native"] = adapter.Enrollment()
	}
	if h.chrome != nil && h.webControl != nil {
		adapter, err := objective.NewWebWithOptions(objective.WebOptions{Read: h.readWebPredicate, ResolveIdentity: h.resolveWebPostconditionIdentity})
		if err != nil {
			return nil, err
		}
		enrolled["web"] = adapter.Enrollment()
	}
	if len(enrolled) == 0 {
		return nil, nil
	}
	return objective.New(enrolled)
}

func (h *Host) readNativePredicate(ctx context.Context, p auth.Principal, target model.Selector, attribute string) (model.Value, objective.NativeEvidence, error) {
	user, err := h.authorize(ctx, p)
	if err != nil {
		return model.Value{}, objective.NativeEvidence{}, err
	}
	permitted := user.DesktopAccess
	for _, bundle := range user.NativeBundles {
		if bundle == target.Surface.BundleID {
			permitted = true
		}
	}
	if !permitted || target.Surface.Kind != "native" {
		return model.Value{}, objective.NativeEvidence{}, auth.ErrUnauthorized
	}
	gateway := h.nativeFor(p.Namespace)
	if gateway == nil {
		return model.Value{}, objective.NativeEvidence{}, ErrNativeControlUnqualified
	}
	lease, err := h.AuthorizeOperation(ctx, p, target.Surface, false, consent.Observe)
	if err != nil {
		return model.Value{}, objective.NativeEvidence{}, err
	}
	defer lease.Release()
	step := model.Step{ID: "native-predicate-read", Action: "element.read", Target: target, TimeoutMs: 10000, Effect: model.Effect{Class: model.ReadOnly}, Arguments: map[string]model.Value{"attribute": {Kind: model.StringValue, String: attribute}}}
	result, err := gateway.Execute(lease.Context, p, step, nil)
	if err != nil {
		return model.Value{}, objective.NativeEvidence{}, nativePredicateError(err)
	}
	if result.Value == nil || result.Observation == nil || len(result.Observation.Nodes) != 1 {
		return model.Value{}, objective.NativeEvidence{}, errors.New("independent native read evidence unavailable")
	}
	proof := result.Observation
	return *result.Value, objective.NativeEvidence{HelperEpoch: proof.Epoch, TargetRef: proof.Nodes[0].Ref.ID, ObservedAt: proof.Ended}, nil
}

// matchNativeLiteral compares classified nonsecure plaintext without returning
// the field value. It requires control consent even though the operation is read-only.
func (h *Host) matchNativeLiteral(ctx context.Context, p auth.Principal, target model.Selector, expected string) (bool, objective.NativeEvidence, error) {
	if !p.HasScope("desktop:control") {
		return false, objective.NativeEvidence{}, auth.ErrUnauthorized
	}
	user, err := h.authorize(ctx, p)
	if err != nil {
		return false, objective.NativeEvidence{}, err
	}
	permitted := user.DesktopAccess
	for _, bundle := range user.NativeBundles {
		permitted = permitted || bundle == target.Surface.BundleID
	}
	if !permitted || target.Surface.Kind != "native" || target.Surface.ProcessID <= 0 {
		return false, objective.NativeEvidence{}, auth.ErrUnauthorized
	}
	gateway := h.nativeFor(p.Namespace)
	if gateway == nil {
		return false, objective.NativeEvidence{}, ErrNativeControlUnqualified
	}
	lease, err := h.AuthorizeOperation(ctx, p, target.Surface, false, consent.Control)
	if err != nil {
		return false, objective.NativeEvidence{}, err
	}
	defer lease.Release()
	proof, err := gateway.ValueMatches(lease.Context, p, target, expected)
	if err != nil {
		return false, objective.NativeEvidence{}, nativePredicateError(err)
	}
	return proof.Matches, objective.NativeEvidence{HelperEpoch: proof.HelperEpoch, TargetRef: proof.TargetRef, ObservedAt: proof.ObservedAt}, nil
}
