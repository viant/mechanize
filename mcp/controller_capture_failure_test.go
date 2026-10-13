package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/model"
)

func TestControllerCanonicalCaptureFailures(t *testing.T) {
	for _, name := range []string{"mechanize_capture", "mechanize_capture_window_frame"} {
		for _, tc := range []struct {
			code, dispatch, want string
			cleanup              bool
		}{
			{"staleReference", "notDispatched", "staleReference", true},
			{"staleEpoch", "notDispatched", "staleEpoch", true},
			{"targetNotFound", "notDispatched", "targetNotFound", true},
			{"permissionDenied", "notDispatched", "permissionDenied", true},
			{"captureUnqualified", "notDispatched", "captureUnqualified", true},
			{"captureTooLarge", "dispatched", "captureTooLarge", true},
			{"captureOffDisplay", "notDispatched", "captureOffDisplay", true},
			{"captureAmbiguousDisplay", "notDispatched", "captureAmbiguousDisplay", true},
			{"unavailable", "unknown", "captureFailed", false},
			{"RAW_CANARY", "RAW_CANARY", "captureFailed", false},
		} {
			t.Run(name+"/"+tc.code, func(t *testing.T) {
				failure := &native.CaptureError{Cause: &native.NativeError{Code: tc.code, Message: "RAW_CANARY"}, DispatchState: tc.dispatch, CleanupConfirmed: tc.cleanup}
				d, id, ctx, _ := controllerFixture(t, func(deps *Dependencies) {
					deps.CaptureWindow = func(context.Context, auth.Principal, model.Surface, int32, uint32) (data.ArtifactReference, native.CapturedImage, error) {
						return data.ArtifactReference{}, native.CapturedImage{}, failure
					}
					deps.CaptureWindowFrame = func(context.Context, auth.Principal, model.Surface, int32, uint32) (data.ArtifactReference, data.ArtifactReference, native.WindowFrameCapture, error) {
						return data.ArtifactReference{}, data.ArtifactReference{}, native.WindowFrameCapture{}, failure
					}
				})
				session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{"name": "capture failure"}))["sessionId"].(string)
				out := controllerCall(t, d, ctx, id, name, CaptureWindowInput{SessionID: session, GrantID: "fixture-grant", Purpose: "Observe fixture", Surface: model.Surface{Kind: "native", BundleID: "com.example.Fixture", ProcessID: 71, ProcessStartToken: "71:1"}, PID: 71, WindowID: 2})
				body := controllerBody(t, out)
				wantDispatch := tc.dispatch
				if wantDispatch == "RAW_CANARY" {
					wantDispatch = "unknown"
				}
				if out.IsError == nil || !*out.IsError || body["code"] != tc.want || body["dispatchState"] != wantDispatch || body["cleanupConfirmed"] != tc.cleanup {
					t.Fatalf("capture failure metadata lost: %+v", body)
				}
				encoded, _ := json.Marshal(out)
				if strings.Contains(string(encoded), "RAW_CANARY") || len(out.Content) != 1 {
					t.Fatalf("unsafe capture projection: %s", encoded)
				}
				if body["message"] == "" {
					t.Fatal("recovery advice missing")
				}
			})
		}
	}
}

func TestControllerCanonicalFrameTypedFailures(t *testing.T) {
	for _, name := range []string{"mechanize_capture", "mechanize_capture_window_frame"} {
		for _, code := range []string{"staleFramePermit", "windowFrameUnconfirmed", "captureEvidenceMismatch", "RAW_CANARY"} {
			t.Run(name+"/"+code, func(t *testing.T) {
				typed := &model.MechanizeError{Code: code, Message: "RAW_CANARY", Stage: "RAW_CANARY", DispatchState: "unknown", EffectState: "RAW_CANARY"}
				d, id, ctx, _ := controllerFixture(t, func(deps *Dependencies) {
					deps.CaptureWindow = func(context.Context, auth.Principal, model.Surface, int32, uint32) (data.ArtifactReference, native.CapturedImage, error) {
						return data.ArtifactReference{}, native.CapturedImage{}, typed
					}
					deps.CaptureWindowFrame = func(context.Context, auth.Principal, model.Surface, int32, uint32) (data.ArtifactReference, data.ArtifactReference, native.WindowFrameCapture, error) {
						return data.ArtifactReference{}, data.ArtifactReference{}, native.WindowFrameCapture{}, typed
					}
				})
				session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{"name": "frame failure"}))["sessionId"].(string)
				out := controllerCall(t, d, ctx, id, name, CaptureWindowInput{SessionID: session, GrantID: "fixture-grant", Purpose: "Observe fixture", Surface: model.Surface{Kind: "native", BundleID: "com.example.Fixture", ProcessID: 71, ProcessStartToken: "71:1"}, PID: 71, WindowID: 2})
				body := controllerBody(t, out)
				want := code
				if code == "RAW_CANARY" {
					want = "captureFailed"
				}
				if body["code"] != want || body["dispatchState"] != "unknown" || body["cleanupConfirmed"] != nil {
					t.Fatalf("wrong typed failure projection: %+v", body)
				}
				encoded, _ := json.Marshal(out)
				if strings.Contains(string(encoded), "RAW_CANARY") {
					t.Fatalf("raw failure leaked: %s", encoded)
				}
			})
		}
	}
}

func TestControllerCanonicalCaptureRetainedPublication(t *testing.T) {
	for _, name := range []string{"mechanize_capture", "mechanize_capture_window_frame"} {
		for _, mode := range []string{"retained", "malformed-phase", "malformed-ref"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				ref := data.ArtifactReference{ID: "fixture-artifact", ContentHash: strings.Repeat("a", 64), SizeBytes: 8, MediaType: "image/png", KeyReference: "fixture-v1"}
				phase, cause := "verify", "verificationUnavailable"
				if mode == "malformed-phase" {
					phase, cause = "RAW_CANARY", "RAW_CANARY"
				}
				if mode == "malformed-ref" {
					ref.ContentHash = "RAW_CANARY"
				}
				publication := &fixtureCapturePublication{ref: ref, phase: phase, cause: cause}
				d, id, ctx, _ := controllerFixture(t, func(deps *Dependencies) {
					deps.CaptureWindow = func(context.Context, auth.Principal, model.Surface, int32, uint32) (data.ArtifactReference, native.CapturedImage, error) {
						return ref, native.CapturedImage{}, publication
					}
					deps.CaptureWindowFrame = func(context.Context, auth.Principal, model.Surface, int32, uint32) (data.ArtifactReference, data.ArtifactReference, native.WindowFrameCapture, error) {
						return ref, data.ArtifactReference{}, native.WindowFrameCapture{}, publication
					}
				})
				session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{"name": "publication failure"}))["sessionId"].(string)
				out := controllerCall(t, d, ctx, id, name, CaptureWindowInput{SessionID: session, GrantID: "fixture-grant", Purpose: "Observe fixture", Surface: model.Surface{Kind: "native", BundleID: "com.example.Fixture", ProcessID: 71, ProcessStartToken: "71:1"}, PID: 71, WindowID: 2})
				body := controllerBody(t, out)
				if mode == "malformed-ref" {
					if body["code"] != "captureFailed" || body["artifact"] != nil {
						t.Fatalf("malformed artifact projected: %+v", body)
					}
				} else {
					if body["code"] != "artifactPublicationUnconfirmed" || body["dispatchState"] != "dispatched" || body["publicationState"] != "unknown" || body["publicationConfirmed"] != false || body["imageReturned"] != false {
						t.Fatalf("publication semantics lost: %+v", body)
					}
					encodedRef, _ := json.Marshal(body["artifact"])
					var retained data.ArtifactReference
					if json.Unmarshal(encodedRef, &retained) != nil || retained != ref {
						t.Fatalf("retained opaque reference lost: %+v", retained)
					}
					if mode == "malformed-phase" {
						phase, cause = "unknown", "metadataUnavailable"
					}
					if body["publicationPhase"] != phase || body["publicationCause"] != cause {
						t.Fatalf("wrong closed diagnostic: %+v", body)
					}
				}
				encoded, _ := json.Marshal(out)
				if strings.Contains(string(encoded), "RAW_CANARY") || len(out.Content) != 1 || out.IsError == nil || !*out.IsError {
					t.Fatalf("unsafe publication projection: %s", encoded)
				}
			})
		}
	}
}
