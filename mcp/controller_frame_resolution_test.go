package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/model"
)

func controllerFramePNG(t *testing.T, width, height, noisyRows int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for i := 3; i < len(img.Pix); i += 4 {
		img.Pix[i] = 255
	}
	rng := rand.New(rand.NewSource(37))
	for y := 0; y < noisyRows; y++ {
		for x := 0; x < width; x++ {
			img.SetRGBA(x, y, color.RGBA{R: uint8(rng.Intn(256)), G: uint8(rng.Intn(256)), B: uint8(rng.Intn(256)), A: 255})
		}
	}
	var buffer bytes.Buffer
	if err := png.Encode(&buffer, img); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestControllerCanonicalFrameCaptureImageResolution(t *testing.T) {
	for _, fixture := range []struct {
		name                     string
		width, height, noisyRows int
		preview                  bool
	}{
		{"original", 2612, 1552, 200, false},
		{"oversized-preview", 2048, 1536, 1536, true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			source := controllerFramePNG(t, fixture.width, fixture.height, fixture.noisyRows)
			if (len(source) > MaximumInlineCaptureBytes) != fixture.preview || len(source) <= 96*1024 {
				t.Fatal("fixture does not distinguish canonical and former preview budgets", len(source))
			}
			hash := sha256.Sum256(source)
			digest := hex.EncodeToString(hash[:])
			imageRef := data.ArtifactReference{ID: "fixture-image", ContentHash: digest, MediaType: "image/png", SizeBytes: len(source)}
			provenance := data.ArtifactReference{ID: "fixture-provenance", MediaType: "application/json"}
			var permit native.WindowFramePermit
			calls := 0
			d, id, ctx, actions := controllerFixture(t, func(deps *Dependencies) {
				deps.CaptureWindowFrame = func(ctx context.Context, p auth.Principal, surface model.Surface, pid int32, window uint32) (data.ArtifactReference, data.ArtifactReference, native.WindowFrameCapture, error) {
					calls++
					binding, _ := auth.ConsentBindingFromContext(ctx)
					permit = native.WindowFramePermit{ID: "original-permit", Owner: native.WindowFrameOwner{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: binding.SessionID}, BundleID: surface.BundleID, PID: int(pid), ProcessStartToken: surface.ProcessStartToken, WindowID: window, ContentHash: digest, Width: fixture.width, Height: fixture.height, Scale: 2, Bounds: native.CaptureBounds{X: -100, Y: 20, Width: float64(fixture.width) / 2, Height: float64(fixture.height) / 2}, ExpiresAt: time.Now().Add(30 * time.Second)}
					return imageRef, provenance, native.WindowFrameCapture{Permit: permit, PNG: source}, nil
				}
			})
			session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{}))["sessionId"].(string)
			out := controllerCall(t, d, ctx, id, "mechanize_capture_window_frame", CaptureWindowInput{SessionID: session, GrantID: "fixture-grant", Purpose: "Inspect fixture window", Surface: model.Surface{Kind: "native", BundleID: "com.example.Fixture", ProcessID: 71, ProcessStartToken: "71:1"}, PID: 71, WindowID: 2})
			if out.IsError != nil && *out.IsError || calls != 1 || actions.Load() != 0 {
				t.Fatal("canonical frame capture failed or performed extra input")
			}
			body := controllerBody(t, out)
			expected, _ := result(WindowFrameCaptureResult{Artifact: imageRef, Provenance: provenance, Metadata: permit})
			identity := controllerBody(t, expected)
			for _, field := range []string{"artifact", "provenance", "metadata"} {
				if !reflect.DeepEqual(body[field], identity[field]) {
					t.Fatal("original identity changed", field)
				}
			}
			if body["imageReturned"] != true || body["imageIsPreview"] != fixture.preview || body["captureRef"] != permit.ID {
				t.Fatal("image or permit classification changed")
			}
			inline, err := controllerImage(out)
			if err != nil || inline == nil {
				t.Fatal("single image missing", err)
			}
			pixels, err := base64.StdEncoding.Strict().DecodeString(inline.Data)
			if err != nil || len(pixels) > MaximumInlineCaptureBytes {
				t.Fatal("canonical inline image budget exceeded", err)
			}
			if !fixture.preview {
				if !bytes.Equal(pixels, source) || inline.MimeType != "image/png" || body["preview"] != nil {
					t.Fatal("original pixels were replaced by a derivative")
				}
			} else {
				preview := body["preview"].(map[string]any)
				width, height := preview["widthPixels"].(float64), preview["heightPixels"].(float64)
				if preview["available"] != true || preview["isPreview"] != true || width >= float64(fixture.width) || height >= float64(fixture.height) || preview["scaleX"] != permit.Bounds.Width/width || preview["scaleY"] != permit.Bounds.Height/height || bytes.Equal(pixels, source) {
					t.Fatal("oversized derivative lost explicit original-space mapping")
				}
			}
		})
	}
}

func TestControllerOriginalFrameRejectsInvalidEvidence(t *testing.T) {
	source := controllerFramePNG(t, 80, 40, 40)
	hash := sha256.Sum256(source)
	digest := hex.EncodeToString(hash[:])
	for _, mode := range []string{"size", "hash", "metadataHash", "dimensions", "mapping", "PNG", "base64", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			frame := WindowFrameCaptureResult{Artifact: data.ArtifactReference{ID: "source", SizeBytes: len(source), ContentHash: digest, MediaType: "image/png"}, Metadata: native.WindowFramePermit{ContentHash: digest, Width: 80, Height: 40, Scale: 1, Bounds: native.CaptureBounds{Width: 80, Height: 40}}}
			image := schema.ImageContent{Type: "image", MimeType: "image/png", Data: base64.StdEncoding.EncodeToString(source)}
			switch mode {
			case "size":
				frame.Artifact.SizeBytes++
			case "hash":
				frame.Artifact.ContentHash = "wrong"
			case "metadataHash":
				frame.Metadata.ContentHash = "wrong"
			case "dimensions":
				frame.Metadata.Width, frame.Metadata.Bounds.Width = 81, 81
			case "mapping":
				frame.Metadata.Scale = 2
			case "PNG":
				bad := []byte("PRIVATE_INVALID_PNG_CANARY")
				hash := sha256.Sum256(bad)
				frame.Artifact.SizeBytes, frame.Artifact.ContentHash = len(bad), hex.EncodeToString(hash[:])
				frame.Metadata.ContentHash = frame.Artifact.ContentHash
				image.Data = base64.StdEncoding.EncodeToString(bad)
			case "base64":
				image.Data = "PRIVATE_INVALID_BASE64_CANARY"
			}
			answer := &schema.CallToolResult{Content: []schema.CallToolResultContentElem{image}}
			if mode == "duplicate" {
				answer.Content = append(answer.Content, image)
			}
			encoded, _ := json.Marshal(frame)
			out, err := projectControllerCapture(context.Background(), "mechanize_capture_window_frame", encoded, answer)
			wire, _ := json.Marshal(out)
			if err != nil || out.IsError == nil || !*out.IsError || bytes.Contains(wire, []byte("PRIVATE_")) {
				t.Fatal("invalid evidence was exposed", err)
			}
		})
	}
}
