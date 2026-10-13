package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	integration "github.com/viant/mechanize/integration/endly"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

// Actual encrypted Put and bound metadata storage initialization failure. This public
// synthetic fixture supplies the physical capture and trusted consent lease;
// the existing Host consent/capture fixture covers real grant consumption.
func TestCapturePublicationFailureStillReturnsOwnedObservation(t *testing.T) {
	service, ctx, p, root, options := artifactFixture(t)
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, image.NewRGBA(image.Rect(0, 0, 4, 4))); err != nil {
		t.Fatal(err)
	}
	pixels := encoded.Bytes()
	metadataParent := filepath.Join(t.TempDir(), "unavailable-metadata-parent")
	if err := os.WriteFile(metadataParent, []byte("synthetic storage fault"), 0600); err != nil {
		t.Fatal(err)
	}
	builder, err := durable.New(durable.Options{SourceRoot: filepath.Join(t.TempDir(), "missing-source"), StorageRoot: filepath.Join(metadataParent, "storage"), VerifyArtifact: service.VerifyArtifact, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 0, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		return integration.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close(context.Background())
	publicationCalls, captureCalls, releases := 0, 0, 0
	options.Publish = func(ctx context.Context, p auth.Principal, ref data.ArtifactReference) error {
		publicationCalls++
		return builder.PublishArtifact(ctx, p, ref)
	}
	h := &Host{artifacts: service, captureHelper: "synthetic-boundary", captureMaxBytes: 1024}
	h.captureWindow = func(context.Context, native.WindowCaptureOptions) (native.CapturedImage, error) {
		captureCalls++
		return native.CapturedImage{PNG: pixels, Metadata: native.CaptureMetadata{BundleID: "fixture.app", PID: 123, WindowID: 42, Identity: "window:42", Bytes: len(pixels), Width: 4, Height: 4, ProcessStartToken: "1:1"}}, nil
	}
	runtime, err := integration.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		return integration.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var retained data.ArtifactReference
	server, err := gateway.New(gateway.Dependencies{Runtime: runtime, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, CaptureWindow: func(ctx context.Context, actual auth.Principal, surface model.Surface, pid int32, window uint32) (data.ArtifactReference, native.CapturedImage, error) {
		if actual.Namespace != p.Namespace {
			t.Fatal("owner changed")
		}
		ref, img, err := h.captureWindowWithLease(actual, surface, pid, window, &consent.Lease{Context: ctx, Release: func() { releases++ }})
		retained = ref
		return ref, img, err
	}})
	if err != nil {
		t.Fatal(err)
	}
	client := server.AsClient(ctx)
	result, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_capture", Arguments: map[string]any{"sessionId": "fixture-session", "grantId": "fixture-grant", "purpose": "Observe public synthetic fixture", "surface": map[string]any{"kind": "native", "bundleId": "fixture.app", "processId": 123, "processStartToken": "1:1"}, "pid": 123, "windowId": 42}})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError != nil && *result.IsError {
		t.Fatal("metadata storage failure erased captured pixels")
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Structured map[string]any                `json:"structuredContent"`
		Content    []struct{ Type, Data string } `json:"content"`
	}
	if err = json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Structured["publicationState"] != "unknown" || wire.Structured["publicationConfirmed"] != false || wire.Structured["publicationPhase"] != "bind" || wire.Structured["publicationCause"] != "metadataSourceUnavailable" {
		t.Fatal("metadata uncertainty was lost")
	}
	images := 0
	for _, item := range wire.Content {
		if item.Type == "image" {
			images++
			decoded, decodeErr := base64.StdEncoding.DecodeString(item.Data)
			if decodeErr != nil || !bytes.Equal(decoded, pixels) {
				t.Fatal("capture bytes changed")
			}
		}
	}
	if images != 1 || captureCalls != 1 || publicationCalls != 1 || releases != 1 {
		t.Fatalf("images %d capture %d publication %d release %d", images, captureCalls, publicationCalls, releases)
	}
	if err = service.VerifyArtifact(ctx, p, retained); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(filepath.Join(root, p.Namespace, retained.ID))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, pixels) {
		t.Fatal("unencrypted image persisted")
	}
	entries, err := os.ReadDir(filepath.Join(root, p.Namespace))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatal("capture or publication was repeated")
	}
	if bytes.Contains(raw, []byte("component")) || bytes.Contains(raw, []byte("private database path")) {
		t.Fatal("internal source details exposed")
	}
}
