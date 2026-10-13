package darwin

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

func TestWindowFrameLocalExpiryAlreadyProjectsThroughOriginalRuntime(t *testing.T) {
	ctx, p, g, helper, surface := frameGatewayFixture(t, "")
	runtime, err := integration.New(g.Execute)
	if err != nil {
		t.Fatal(err)
	}
	session, err := runtime.Open(ctx, "expired local frame")
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(ctx, session.SessionID)
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: session.SessionID, GrantID: "grant", Purpose: "Frame click"})
	helper.owner.SessionID = session.SessionID
	if _, err = g.CaptureWindowFrame(ctx, p, surface, 17); err != nil {
		t.Fatal(err)
	}
	g.framePermit.ExpiresAt = time.Now().Add(-time.Second)
	expired := g.framePermit.ExpiresAt
	calls := len(helper.calls)
	operation, err := runtime.StartPlan(ctx, session.SessionID, model.Plan{SchemaVersion: 1, Steps: []model.Step{frameClickStep(t)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	done, err := runtime.Wait(wait, session.SessionID, operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	diagnostic, err := runtime.ExecutionFailure(ctx, session.SessionID, operation.ID)
	if err != nil || diagnostic == nil || diagnostic.Code != "staleFramePermit" || diagnostic.DispatchState != "notDispatched" || done.Status != "failed" {
		t.Fatalf("local expiry diagnostic: %+v %v", diagnostic, err)
	}
	if helper.clicks != 0 || len(helper.calls) != calls || g.framePermit == nil || !g.framePermit.ExpiresAt.Equal(expired) {
		t.Fatal("local rejection performed I/O, consumed or extended permit")
	}
}

func TestWindowFrameHelperDiagnosticsRequireCorrelatedNativeReply(t *testing.T) {
	client := fixtureClient(t)
	for _, code := range []string{"stalePermit", "windowClickOccluded", "windowHitTestUnavailable", "windowClickUnqualified"} {
		for _, mode := range []string{"qualified", "unknown", "conflict", "wrongEpoch", "wrongStage", "constructed", "localName"} {
			t.Run(code+"/"+mode, func(t *testing.T) {
				requestCode, stage, epoch, state := code, "native", "fixture-epoch", "notDispatched"
				if mode == "unknown" {
					state = "unknown"
				}
				if mode == "wrongEpoch" {
					epoch = "other-epoch"
				}
				if mode == "wrongStage" {
					stage = "other"
				}
				if mode == "localName" {
					requestCode = "staleFramePermit"
				}
				params, _ := json.Marshal(map[string]string{"code": requestCode, "state": state, "stage": stage})
				reply, err := client.Call(context.Background(), Request{RequestID: code + "-" + mode, HelperEpoch: epoch, Method: "fixture.nativeDiagnostic", Params: params, DeadlineRemainingMS: 1000})
				if err == nil {
					t.Fatal("fixture reply did not reject")
				}
				if mode == "constructed" {
					err = &NativeError{Code: code, Stage: "native", DispatchState: "notDispatched", Message: "PRIVATE_CANARY"}
				}
				result := integration.StepResult{DispatchState: reply.Receipt.DispatchState}
				if mode == "conflict" {
					result.DispatchState = "unknown"
				}
				failure := integration.CaptureExecutionFailure(result, err)
				if mode == "wrongEpoch" || mode == "wrongStage" || mode == "constructed" || mode == "localName" {
					if failure != nil {
						t.Fatal("unqualified or wrong-provenance frame failure promoted", failure)
					}
					return
				}
				want := "notDispatched"
				if mode == "unknown" || mode == "conflict" {
					want = "unknown"
				}
				if failure == nil || failure.Code != code || failure.DispatchState != want || !failure.Valid() {
					t.Fatalf("closed helper diagnostic lost: %+v", failure)
				}
				raw, _ := json.Marshal(failure)
				if strings.Contains(string(raw), "PRIVATE_CANARY") || strings.Contains(string(raw), "private.test") {
					t.Fatal("raw helper error escaped")
				}
			})
		}
	}
}

func TestWindowFrameUnknownTransportNeverBecomesKnownRejection(t *testing.T) {
	ctx, p, g, helper, surface := frameGatewayFixture(t, "transport")
	if _, err := g.CaptureWindowFrame(ctx, p, surface, 17); err != nil {
		t.Fatal(err)
	}
	result, err := g.Execute(ctx, p, frameClickStep(t), nil)
	if err == nil || result.DispatchState != "unknown" || helper.clicks != 1 {
		t.Fatal("transport uncertainty lost")
	}
	if failure := integration.CaptureExecutionFailure(result, err); failure != nil && failure.DispatchState != "unknown" {
		t.Fatal("unknown input became known rejection", failure)
	}
	if _, err = g.Execute(ctx, p, frameClickStep(t), nil); err == nil || helper.clicks != 1 {
		t.Fatal("uncertain input replayed")
	}
}
