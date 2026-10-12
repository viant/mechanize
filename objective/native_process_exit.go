package objective

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

type NativeProcessExitRead func(context.Context, auth.Principal, model.Surface) (bool, NativeEvidence, error)
type NativeProcessExitAdapter struct{ read NativeProcessExitRead }

func NewNativeProcessExit(read NativeProcessExitRead) (*NativeProcessExitAdapter, error) {
	if read == nil {
		return nil, errors.New("qualified process-exit reader required")
	}
	return &NativeProcessExitAdapter{read: read}, nil
}
func (a *NativeProcessExitAdapter) Enrollment() Enrollment {
	return Enrollment{Adapter: a, MaximumAuthority: Observational, AllowedPredicates: map[string]bool{"exited": true}}
}
func (a *NativeProcessExitAdapter) Evaluate(ctx context.Context, p auth.Principal, name string, inputs map[string]model.Value) (Result, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || (!p.HasScope("desktop:observe") && !p.HasScope("desktop:control")) {
		return Result{}, auth.ErrUnauthorized
	}
	if a == nil || a.read == nil || name != "exited" || len(inputs) != 3 {
		return Result{}, errors.New("exact process exit predicate required")
	}
	bundle, err := boundedNativeString(inputs["bundleID"], 255, false)
	if err != nil {
		return Result{}, err
	}
	token, err := boundedNativeString(inputs["processStartToken"], 27, false)
	if err != nil {
		return Result{}, err
	}
	pid := inputs["processId"]
	if pid.Kind != model.NumberValue || pid.Validate() != nil || pid.Number <= 0 || pid.Number > 2147483647 {
		return Result{}, errors.New("original process PID required")
	}
	surface := model.Surface{Kind: "native", BundleID: bundle, ProcessID: int(pid.Number), ProcessStartToken: token}
	if err := (model.Selector{Surface: surface, Cardinality: "one"}).Validate(); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	exited, proof, err := a.read(ctx, p, surface)
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if !nativeEvidenceID(proof.HelperEpoch) || !nativeEvidenceID(proof.TargetRef) || proof.ObservedAt.IsZero() {
		return Result{Truth: Unknown, Authority: Observational, Reason: "process exit evidence incomplete"}, nil
	}
	reference, _ := json.Marshal(struct {
		HelperEpoch string `json:"helperEpoch"`
		TargetRef   string `json:"targetRef"`
	}{proof.HelperEpoch, proof.TargetRef})
	truth := False
	if exited {
		truth = True
	}
	return Result{Truth: truth, Authority: Observational, ObservedAt: proof.ObservedAt, Evidence: []Evidence{{Kind: "nativeProcessExit", Reference: string(reference)}}}, nil
}
