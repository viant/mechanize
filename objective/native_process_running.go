package objective

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

type NativeProcessRunningRead func(context.Context, auth.Principal, model.Surface) (bool, NativeEvidence, error)
type NativeProcessRunningAdapter struct{ read NativeProcessRunningRead }

func NewNativeProcessRunning(read NativeProcessRunningRead) (*NativeProcessRunningAdapter, error) {
	if read == nil {
		return nil, errors.New("qualified process-running reader required")
	}
	return &NativeProcessRunningAdapter{read: read}, nil
}
func (a *NativeProcessRunningAdapter) Enrollment() Enrollment {
	return Enrollment{Adapter: a, MaximumAuthority: Observational, AllowedPredicates: map[string]bool{"running": true}}
}
func (a *NativeProcessRunningAdapter) Evaluate(ctx context.Context, p auth.Principal, name string, inputs map[string]model.Value) (Result, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || (!p.HasScope("desktop:observe") && !p.HasScope("desktop:control")) {
		return Result{}, auth.ErrUnauthorized
	}
	if a == nil || a.read == nil || name != "running" || len(inputs) != 3 {
		return Result{}, errors.New("exact process running predicate required")
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
	running, proof, err := a.read(ctx, p, surface)
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if !nativeEvidenceID(proof.HelperEpoch) || !nativeEvidenceID(proof.TargetRef) || proof.ObservedAt.IsZero() {
		return Result{Truth: Unknown, Authority: Observational, Reason: "process running evidence incomplete"}, nil
	}
	reference, _ := json.Marshal(struct {
		HelperEpoch string `json:"helperEpoch"`
		TargetRef   string `json:"targetRef"`
	}{proof.HelperEpoch, proof.TargetRef})
	truth := False
	if running {
		truth = True
	}
	return Result{Truth: truth, Authority: Observational, ObservedAt: proof.ObservedAt, Evidence: []Evidence{{Kind: "nativeProcessRunning", Reference: string(reference)}}}, nil
}
