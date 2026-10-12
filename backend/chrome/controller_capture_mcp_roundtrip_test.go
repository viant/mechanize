package chrome_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/png"
	"math/rand"
	"testing"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/data"
	automation "github.com/viant/mechanize/integration/endly"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestCanonicalControllerCaptureSurvivesNativeChunksAndExtension(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 320, 320))
	_, _ = rand.New(rand.NewSource(62)).Read(img.Pix)
	for i := 3; i < len(img.Pix); i += 4 {
		img.Pix[i] = 255
	}
	var pngBytes bytes.Buffer
	if e := png.Encode(&pngBytes, img); e != nil {
		t.Fatal(e)
	}
	pixels := pngBytes.Bytes()
	if len(pixels) < 120*1024 || len(pixels) > 500*1024 {
		t.Fatal("fixture not in requested real-image range", len(pixels))
	}
	digest := sha256.Sum256(pixels)
	p, _ := auth.NewPrincipal("fixture", "", "capture-controller", []string{"desktop:observe"})
	p.ClientID = "controller:capture"
	p.ClientName = "Capture fixture"
	ctx := auth.WithPrincipal(context.Background(), p)
	rt, e := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("capture dispatched business input")
		return automation.StepResult{}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	captures := 0
	server, e := gateway.New(gateway.Dependencies{Runtime: rt, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, CaptureWindow: func(c context.Context, actor auth.Principal, s model.Surface, pid int32, window uint32) (data.ArtifactReference, native.CapturedImage, error) {
		binding, ok := auth.ConsentBindingFromContext(c)
		if !ok || binding.SessionID == "" || actor.ClientID != p.ClientID || auth.NativeHuman(c) {
			t.Fatal("capture identity changed")
		}
		captures++
		return data.ArtifactReference{ID: "fixture-artifact", ContentHash: hex.EncodeToString(digest[:]), SizeBytes: len(pixels), MediaType: "image/png", KeyReference: "fixture-key"}, native.CapturedImage{PNG: pixels, Metadata: native.CaptureMetadata{BundleID: s.BundleID, PID: pid, WindowID: window, Identity: "window:42", Bytes: len(pixels), Width: 320, Height: 320, Scale: 1, CoordinateSpace: "globalLogicalPoints", Bounds: native.CaptureBounds{Width: 320, Height: 320}}}, nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	d, e := gateway.NewControllerDispatcher(server, rt)
	if e != nil {
		t.Fatal(e)
	}
	id := chrome.ControllerIdentity{Principal: p, ConversationID: "capture-connection", Origin: "https://shell.fixture.test", DocumentID: "controller-document"}
	call := func(name string, args any) *schema.CallToolResult {
		t.Helper()
		raw, _ := json.Marshal(args)
		out, e := d.CallTool(ctx, id, chrome.ControllerToolCall{Name: name, Arguments: raw})
		if e != nil || out == nil || out.IsError != nil && *out.IsError {
			t.Fatal("canonical controller call failed", e, out)
		}
		return out
	}
	opened := call("mechanize_session_open", map[string]any{"name": "capture"})
	raw, _ := json.Marshal(opened.StructuredContent)
	var session gateway.SessionRef
	_ = json.Unmarshal(raw, &session)
	answer := call("mechanize_capture", gateway.CaptureWindowInput{SessionID: session.SessionID, Purpose: "Inspect public window", Surface: model.Surface{Kind: "native", BundleID: "fixture.app"}, PID: 123, WindowID: 42})
	raw, _ = json.Marshal(answer.StructuredContent)
	var result gateway.CaptureResult
	_ = json.Unmarshal(raw, &result)
	if !result.ImageReturned || result.ImageIsPreview || result.InlineByteLimit != gateway.MaximumInlineCaptureBytes || result.Artifact.ContentHash != hex.EncodeToString(digest[:]) || len(answer.Content) != 2 {
		t.Fatal("canonical screenshot suppressed or altered")
	}
	image, ok := answer.Content[1].(schema.ImageContent)
	if !ok {
		t.Fatal("image absent")
	}
	decoded, e := base64.StdEncoding.DecodeString(image.Data)
	if e != nil || !bytes.Equal(decoded, pixels) {
		t.Fatal("canonical pixels changed")
	}
	chrome.ControllerProjectedCaptureRoundTripForTest(t, pixels, answer)
	if captures != 1 {
		t.Fatal("capture repeated")
	}
	t.Logf("real PNG %d bytes survived canonical projection, native chunk transfer and extension reassembly", len(pixels))
}
