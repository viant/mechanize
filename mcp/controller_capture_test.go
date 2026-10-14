package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"image"
	"image/color"
	"image/png"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mcp-protocol/schema"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/model"
	bundled "github.com/viant/mechanize/skills"
)

func TestControllerFrameCapturePreviewPreservesOriginalCoordinateAuthority(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 1024, 768))
	rng := rand.New(rand.NewSource(37))
	for y := 0; y < 768; y++ {
		for x := 0; x < 1024; x++ {
			img.SetRGBA(x, y, color.RGBA{uint8(rng.Intn(256)), uint8(rng.Intn(256)), uint8(rng.Intn(256)), 255})
		}
	}
	var buffer bytes.Buffer
	if err := png.Encode(&buffer, img); err != nil {
		t.Fatal(err)
	}
	raw := buffer.Bytes()
	hash := sha256.Sum256(raw)
	digest := hex.EncodeToString(hash[:])
	frame := WindowFrameCaptureResult{CaptureRef: "one-use-permit", Purpose: "Review authorized app", Artifact: data.ArtifactReference{ID: "encrypted-source", SizeBytes: len(raw), ContentHash: digest, MediaType: "image/png"}, Metadata: native.WindowFramePermit{ID: "one-use-permit", ContentHash: digest, Width: 1024, Height: 768, Scale: 2, Bounds: native.CaptureBounds{Width: 512, Height: 384}}, ImageReturned: true}
	encoded, _ := json.Marshal(frame)
	original := &schema.CallToolResult{StructuredContent: frame, Content: []schema.CallToolResultContentElem{schema.TextContent{Type: "text", Text: "UNTRUSTED_TEXT_MUST_NOT_ESCAPE"}, schema.ImageContent{Type: "image", MimeType: "image/png", Data: base64.StdEncoding.EncodeToString(raw)}}}
	out, err := projectControllerCapture(context.Background(), "mechanize_capture_window_frame", encoded, original)
	if err != nil || out == nil || out.IsError != nil && *out.IsError {
		t.Fatal("capture projection failed", err)
	}
	body := controllerBody(t, out)
	if body["captureRef"] != "one-use-permit" || body["imageReturned"] != true || body["imageIsPreview"] != true {
		t.Fatal("permit or preview lost", body)
	}
	meta := body["metadata"].(map[string]any)
	if meta["widthPixels"] != float64(1024) || meta["heightPixels"] != float64(768) {
		t.Fatal("original pixel space changed")
	}
	preview := body["preview"].(map[string]any)
	if preview["available"] != true || preview["isPreview"] != true {
		t.Fatal("preview not labeled")
	}
	wire, _ := json.Marshal(out)
	if bytes.Contains(wire, []byte("UNTRUSTED_TEXT_MUST_NOT_ESCAPE")) {
		t.Fatal("closed projection violated")
	}
	images := 0
	for _, content := range out.Content {
		if c, ok := content.(schema.ImageContent); ok {
			images++
			b, e := base64.StdEncoding.DecodeString(c.Data)
			if e != nil || len(b) > MaximumInlineCaptureBytes {
				t.Fatal("invalid bounded image")
			}
		}
	}
	if images != 1 {
		t.Fatal("preview image missing")
	}
	frame.Artifact.ContentHash = "wrong"
	bad, _ := json.Marshal(frame)
	rejected, _ := projectControllerCapture(context.Background(), "mechanize_capture_window_frame", bad, original)
	if rejected.IsError == nil || !*rejected.IsError {
		t.Fatal("source mismatch admitted")
	}
}

func TestControllerCaptureRequiresOwnedSessionAndRefusesAuthorityConsole(t *testing.T) {
	d, id, ctx, _ := controllerFixture(t)
	session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{"name": "capture owner"}))["sessionId"].(string)
	args := CaptureWindowsInput{SessionID: "foreign-session", Surface: model.Surface{Kind: "native", BundleID: "com.example.Fixture"}, Purpose: "capture"}
	out := controllerCall(t, d, ctx, id, "mechanize_capture_windows", args)
	if out.IsError == nil || !*out.IsError {
		t.Fatal("foreign session accepted")
	}
	args.SessionID = session
	args.Surface.BundleID = "com.viant.mechanize.consent"
	raw, _ := json.Marshal(args)
	if _, _, err := controllerArgs("mechanize_capture_windows", raw); err == nil {
		t.Fatal("controller can inspect its authority console")
	}
	args.Surface.BundleID = "com.example.Fixture"
	raw, _ = json.Marshal(args)
	_, owned, err := controllerArgs("mechanize_capture_windows", raw)
	if err != nil || owned != session {
		t.Fatal("valid discovery input rejected", err)
	}
}

func TestControllerSkillToolsUseCanonicalGuides(t *testing.T) {
	d, id, ctx, _ := controllerFixture(t)
	listed := controllerBody(t, controllerCall(t, d, ctx, id, "skill_list", map[string]any{}))
	folders, err := bundled.Folders()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed["skills"].([]any)) != len(folders) {
		t.Fatal("canonical guides missing")
	}
	got := controllerBody(t, controllerCall(t, d, ctx, id, "skill_get", map[string]any{"uri": "skill://mechanize-desktop/SKILL.md"}))
	if got["entrypointText"] == "" {
		t.Fatal("guide text missing")
	}
	denied := controllerCall(t, d, ctx, id, "mechanize_resource_read", map[string]any{"uri": "file:///arbitrary/private/file"})
	if denied.IsError == nil || !*denied.IsError {
		t.Fatal("arbitrary file read allowed")
	}
}

func TestControllerCanonicalFrameCaptureCatalogAndSessionIsolation(t *testing.T) {
	var count atomic.Int32
	img := image.NewRGBA(image.Rect(0, 0, 80, 40))
	var pngBytes bytes.Buffer
	if err := png.Encode(&pngBytes, img); err != nil {
		t.Fatal(err)
	}
	raw := pngBytes.Bytes()
	hash := sha256.Sum256(raw)
	digest := hex.EncodeToString(hash[:])
	d, id, ctx, _ := controllerFixture(t, func(deps *Dependencies) {
		deps.CaptureWindowFrame = func(ctx context.Context, p auth.Principal, surface model.Surface, pid int32, window uint32) (data.ArtifactReference, data.ArtifactReference, native.WindowFrameCapture, error) {
			count.Add(1)
			binding, ok := auth.ConsentBindingFromContext(ctx)
			if !ok || binding.SessionID == "" || p.ClientID != "controller:fixture" || auth.NativeHuman(ctx) {
				t.Fatal("canonical identity or binding lost")
			}
			permit := native.WindowFramePermit{ID: "owned-frame", Owner: native.WindowFrameOwner{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: binding.SessionID}, BundleID: surface.BundleID, PID: int(pid), ProcessStartToken: surface.ProcessStartToken, WindowID: window, ContentHash: digest, Width: 80, Height: 40, Scale: 1, Bounds: native.CaptureBounds{Width: 80, Height: 40}, ExpiresAt: time.Now().Add(30 * time.Second)}
			return data.ArtifactReference{ID: "image", ContentHash: digest, MediaType: "image/png", SizeBytes: len(raw)}, data.ArtifactReference{ID: "provenance", MediaType: "application/json"}, native.WindowFrameCapture{Permit: permit, PNG: raw}, nil
		}
	})
	listed, err := d.ListTools(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range listed.Tools {
		if tool.Name == "mechanize_capture_window_frame" {
			found = true
		}
	}
	wire, _ := json.Marshal(listed)
	if !found || len(wire) > 192*1024 {
		t.Fatal("capture catalog absent or exceeds bridge budget", len(wire))
	}
	session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{"name": "frame capture"}))["sessionId"].(string)
	input := CaptureWindowInput{SessionID: session, GrantID: "owned-grant", Purpose: "Capture authorized window", Surface: model.Surface{Kind: "native", BundleID: "com.example.Fixture", ProcessID: 71, ProcessStartToken: "71:1"}, PID: 71, WindowID: 2}
	out := controllerCall(t, d, ctx, id, "mechanize_capture_window_frame", input)
	if out.IsError != nil && *out.IsError || count.Load() != 1 {
		t.Fatalf("canonical capture failed: calls=%d result=%+v", count.Load(), out)
	}
	body := controllerBody(t, out)
	if body["captureRef"] != "owned-frame" || body["imageReturned"] != true {
		t.Fatal("capture result lost")
	}
	input.SessionID = "another-session"
	denied := controllerCall(t, d, ctx, id, "mechanize_capture_window_frame", input)
	if denied.IsError == nil || !*denied.IsError || count.Load() != 1 {
		t.Fatal("foreign session reached canonical capture")
	}
}
