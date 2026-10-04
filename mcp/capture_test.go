package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"math/rand"
	"testing"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/data"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestMCPCaptureImageAndBoundedPublication(t *testing.T) {
	for _, mode := range []string{"image", "large", "wrong-scope", "unknown-cleanup", "unknown-publication"} {
		t.Run(mode, func(t *testing.T) {
			p, _ := auth.NewPrincipal("fixture", "", "alice", []string{"desktop:observe"})
			ctx := auth.WithPrincipal(context.Background(), p)
			runtime, err := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
				return automation.StepResult{}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			img := image.NewRGBA(image.Rect(0, 0, 4, 4))
			if mode == "large" {
				img = image.NewRGBA(image.Rect(0, 0, 1024, 600))
				_, _ = rand.New(rand.NewSource(42)).Read(img.Pix)
			}
			var encodedPNG bytes.Buffer
			if err = png.Encode(&encodedPNG, img); err != nil {
				t.Fatal(err)
			}
			pixels := encodedPNG.Bytes()
			if mode == "large" && len(pixels) <= MaximumInlineCaptureBytes {
				t.Fatal("large fixture below limit")
			}
			hash := sha256.Sum256(pixels)
			ref := data.ArtifactReference{ID: "fixture-id", ContentHash: hex.EncodeToString(hash[:]), SizeBytes: len(pixels), MediaType: "image/png", KeyReference: "fixture-v1"}
			calls := 0
			server, err := New(Dependencies{Runtime: runtime, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, CaptureWindow: func(ctx context.Context, actual auth.Principal, surface model.Surface, pid int32, window uint32) (data.ArtifactReference, native.CapturedImage, error) {
				calls++
				binding, ok := auth.ConsentBindingFromContext(ctx)
				if ok && binding.GrantID == "" {
					return data.ArtifactReference{}, native.CapturedImage{}, auth.ErrUnauthorized
				}
				if !ok || binding.SessionID != "session" || binding.GrantID != "grant" || binding.Purpose != "Inspect fixture" || actual.Namespace != p.Namespace || surface.BundleID != "fixture.app" || pid != 123 || window != 42 {
					t.Fatal("capture lost verified consent/scope")
				}
				if mode == "unknown-cleanup" {
					return data.ArtifactReference{}, native.CapturedImage{}, &native.CaptureError{Cause: errors.New("private helper failure"), CleanupConfirmed: false, DispatchState: "unknown"}
				}
				if mode == "unknown-publication" {
					return ref, native.CapturedImage{}, errors.New("private lost commit acknowledgement")
				}
				result := native.CapturedImage{PNG: pixels, Metadata: native.CaptureMetadata{BundleID: "fixture.app", PID: pid, WindowID: window, Identity: "window:42", Bytes: len(pixels), Width: img.Bounds().Dx(), Height: img.Bounds().Dy(), Scale: 1, CoordinateSpace: "globalLogicalPoints", Bounds: native.CaptureBounds{X: -1024, Y: 20, Width: float64(img.Bounds().Dx()), Height: float64(img.Bounds().Dy())}}}
				if mode == "wrong-scope" {
					result.Metadata.BundleID = "other.app"
				}
				return ref, result, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			client := server.AsClient(ctx)
			if _, err = client.Initialize(ctx); err != nil {
				t.Fatal(err)
			}
			args := map[string]any{"sessionId": "session", "purpose": "Inspect fixture", "surface": map[string]any{"kind": "native", "bundleId": "fixture.app"}, "pid": 123, "windowId": 42}
			denied, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_capture", Arguments: args})
			if err != nil || denied.IsError == nil || !*denied.IsError || calls != 1 {
				t.Fatal("capture without matching permanent approval was not denied by authorizer")
			}
			args["grantId"] = "grant"
			r, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_capture", Arguments: args})
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(r)
			var wire struct {
				IsError    bool                                    `json:"isError"`
				Content    []struct{ Type, Data, MimeType string } `json:"content"`
				Structured map[string]any                          `json:"structuredContent"`
			}
			if err = json.Unmarshal(raw, &wire); err != nil {
				t.Fatal(err)
			}
			images := 0
			for _, content := range wire.Content {
				if content.Type == "image" {
					images++
					decoded, err := base64.StdEncoding.DecodeString(content.Data)
					if err != nil || len(decoded) > MaximumInlineCaptureBytes {
						t.Fatal("invalid or oversized inline image")
					}
					if mode == "large" {
						if content.MimeType != "image/jpeg" {
							t.Fatal("large fixture did not return bounded JPEG preview")
						}
						if _, err := jpeg.DecodeConfig(bytes.NewReader(decoded)); err != nil {
							t.Fatal(err)
						}
					} else if content.MimeType != "image/png" || !bytes.Equal(decoded, pixels) {
						t.Fatal("original image content changed")
					}
				}
			}
			switch mode {
			case "image":
				if wire.IsError || images != 1 || wire.Structured["imageReturned"] != true {
					t.Fatalf("missing inline evidence: %s", raw)
				}
			case "large":
				if wire.IsError || images != 1 || wire.Structured["imageReturned"] != true || wire.Structured["imageIsPreview"] != true || wire.Structured["artifact"] == nil || wire.Structured["preview"] == nil {
					t.Fatal("large capture lost publication or preview identity")
				}
				artifact := wire.Structured["artifact"].(map[string]any)
				if artifact["contentHash"] != ref.ContentHash || artifact["sizeBytes"] != float64(len(pixels)) {
					t.Fatal("preview changed original artifact identity")
				}
			case "unknown-cleanup":
				if !wire.IsError || images != 0 || wire.Structured["dispatchState"] != "unknown" || wire.Structured["cleanupConfirmed"] != false {
					t.Fatalf("cleanup uncertainty lost: %s", raw)
				}
			case "unknown-publication":
				if !wire.IsError || images != 0 || wire.Structured["publicationState"] != "unknown" || wire.Structured["artifact"] == nil {
					t.Fatalf("publication uncertainty lost: %s", raw)
				}
			default:
				if !wire.IsError || images != 0 {
					t.Fatal("foreign capture exposed")
				}
			}
			if bytes.Contains(raw, []byte("private helper failure")) || bytes.Contains(raw, []byte("private lost commit")) {
				t.Fatal("internal failure details exposed")
			}
		})
	}
}

func TestCapturePermissionFailureGuidesNativeSetup(t *testing.T) {
	r, rpcErr := captureFailure(&native.CaptureError{Cause: &native.NativeError{Code: "permissionDenied", Message: "private helper detail"}, CleanupConfirmed: true, DispatchState: "unknown"}, data.ArtifactReference{})
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	raw, _ := json.Marshal(r.StructuredContent)
	if !bytes.Contains(raw, []byte("Screen Recording")) || !bytes.Contains(raw, []byte("native permission panel")) || bytes.Contains(raw, []byte("private helper detail")) {
		t.Fatalf("permission guidance lost or leaked: %s", raw)
	}
}

func TestCaptureGeometryFailureIsActionableWithoutPrivateCause(t *testing.T) {
	for _, code := range []string{"captureOffDisplay", "captureAmbiguousDisplay", "captureUnqualified"} {
		t.Run(code, func(t *testing.T) {
			r, rpcErr := captureFailure(&native.CaptureError{Cause: &native.NativeError{Code: code, Message: "private window detail"}, CleanupConfirmed: true, DispatchState: "unknown"}, data.ArtifactReference{})
			if rpcErr != nil {
				t.Fatal(rpcErr)
			}
			body, ok := r.StructuredContent.(map[string]any)
			if !ok || body["code"] != code || body["cleanupConfirmed"] != true || body["dispatchState"] != "unknown" {
				t.Fatal("geometry facts lost", body)
			}
			raw, _ := json.Marshal(body)
			if bytes.Contains(raw, []byte("private window detail")) {
				t.Fatal("private cause leaked")
			}
			if code == "captureOffDisplay" && !bytes.Contains(raw, []byte("move it fully")) {
				t.Fatal("missing actionable guidance")
			}
		})
	}
}
