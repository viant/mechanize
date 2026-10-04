package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/png"
	"math/rand"
	"testing"
	"time"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/data"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestMCPWindowFrameCapturePublishesDedicatedPermitImageAndPurpose(t *testing.T) {
	for _, mode := range []string{"valid", "large", "foreignOwner", "wrongPublication", "expired"} {
		t.Run(mode, func(t *testing.T) {
			p, _ := auth.NewPrincipal("fixture", "", "frame-client", []string{"desktop:observe", "desktop:control"})
			p.ClientID = "frame-client"
			ctx := auth.WithPrincipal(context.Background(), p)
			rt, err := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
				return automation.StepResult{}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			width, height := 4, 4
			if mode == "large" {
				width, height = 1024, 768
			}
			pixels := image.NewRGBA(image.Rect(0, 0, width, height))
			if mode == "large" {
				_, _ = rand.New(rand.NewSource(42)).Read(pixels.Pix)
			}
			var pngBytes bytes.Buffer
			png.Encode(&pngBytes, pixels)
			sum := sha256.Sum256(pngBytes.Bytes())
			imageRef := data.ArtifactReference{ID: "image", ContentHash: hex.EncodeToString(sum[:]), SizeBytes: pngBytes.Len(), MediaType: "image/png", KeyReference: "fixture"}
			provenanceRef := data.ArtifactReference{ID: "provenance", ContentHash: "fixture", SizeBytes: 100, MediaType: "application/json", KeyReference: "fixture"}
			server, err := New(Dependencies{Runtime: rt, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, CaptureWindowFrame: func(call context.Context, actual auth.Principal, surface model.Surface, pid int32, window uint32) (data.ArtifactReference, data.ArtifactReference, native.WindowFrameCapture, error) {
				binding, ok := auth.ConsentBindingFromContext(call)
				if !ok || binding.SessionID != "session" || binding.GrantID != "grant" || binding.Purpose != "Click fixture" || actual.ClientID != p.ClientID || surface.ProcessStartToken != "100:1" || pid != 42 || window != 17 {
					t.Fatal("frame binding changed")
				}
				now := time.Now()
				permit := native.WindowFramePermit{ID: "issued-permit", Owner: native.WindowFrameOwner{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: "session"}, HelperEpoch: "fixture", FenceGeneration: 1, BundleID: "fixture.app", PID: 42, ProcessStartToken: "100:1", WindowID: 17, DisplayID: 1, Bounds: native.CaptureBounds{Width: float64(width), Height: float64(height)}, Width: width, Height: height, Scale: 1, ContentHash: imageRef.ContentHash, CapturedAt: now, ExpiresAt: now.Add(native.WindowFramePermitLifetime)}
				switch mode {
				case "foreignOwner":
					permit.Owner.ClientID = "foreign"
				case "wrongPublication":
					permit.ContentHash = "foreign"
				case "expired":
					permit.ExpiresAt = now.Add(-time.Second)
				}
				return imageRef, provenanceRef, native.WindowFrameCapture{Permit: permit, PNG: pngBytes.Bytes()}, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			client := server.AsClient(ctx)
			if _, err = client.Initialize(ctx); err != nil {
				t.Fatal(err)
			}
			response, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_capture_window_frame", Arguments: map[string]any{"sessionId": "session", "grantId": "grant", "purpose": "Click fixture", "surface": map[string]any{"kind": "native", "bundleId": "fixture.app", "processId": 42, "processStartToken": "100:1"}, "pid": 42, "windowId": 17}})
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(response)
			var wire struct {
				IsError bool `json:"isError"`
				Content []struct {
					Type string `json:"type"`
				} `json:"content"`
				Structured map[string]any `json:"structuredContent"`
			}
			json.Unmarshal(raw, &wire)
			images := 0
			for _, content := range wire.Content {
				if content.Type == "image" {
					images++
				}
			}
			if mode == "valid" || mode == "large" {
				if wire.IsError || images != 1 || wire.Structured["captureRef"] != "issued-permit" || wire.Structured["purpose"] != "Click fixture" || wire.Structured["provenance"] == nil {
					t.Fatal("dedicated capture result lost")
				}
			} else if !wire.IsError || images != 0 {
				t.Fatal("unsafe capture exposed permit/image")
			}
		})
	}
}
