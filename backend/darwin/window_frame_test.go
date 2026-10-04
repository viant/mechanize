package darwin

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
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

type frameFixture struct {
	owner  WindowFrameOwner
	mode   string
	calls  []string
	clicks int
	permit WindowFramePermit
}

func (*frameFixture) Close() error { return nil }
func (f *frameFixture) Call(ctx context.Context, r Request) (Reply, error) {
	if err := ctx.Err(); err != nil {
		return Reply{}, err
	}
	f.calls = append(f.calls, r.Method)
	reply := Reply{HelperEpoch: "fixture", RequestID: r.RequestID}
	switch r.Method {
	case "doctor":
		reply.Result, _ = json.Marshal(map[string]any{"axTrusted": true, "semanticEnabled": true, "captureGranted": f.mode != "noCapture", "windowFrameClickEnabled": f.mode != "noOptIn"})
	case "lease.install":
	case "windows.captureFrame":
		if r.Lease == nil || r.Lease.ID != "held" || r.Lease.Generation != 3 {
			panic("capture missing retained fence")
		}
		var params struct {
			Owner    WindowFrameOwner `json:"owner"`
			Bundle   string           `json:"expectedApp"`
			PID      int              `json:"pid"`
			Birth    string           `json:"processStartToken"`
			WindowID uint32           `json:"windowId"`
		}
		json.Unmarshal(r.Params, &params)
		if params.Owner != f.owner || params.PID != 42 || params.Birth != "100:1" || params.WindowID != 17 || params.Bundle != "fixture.app" {
			panic("capture identity changed")
		}
		width, height := 16, 12
		if f.mode == "large" {
			width, height = 1024, 768
		}
		pixels := image.NewRGBA(image.Rect(0, 0, width, height))
		if f.mode == "large" {
			_, _ = rand.New(rand.NewSource(42)).Read(pixels.Pix)
		}
		var buf bytes.Buffer
		png.Encode(&buf, pixels)
		sum := sha256.Sum256(buf.Bytes())
		now := time.Now()
		permit := WindowFramePermit{ID: "dedicated-permit", Owner: f.owner, HelperEpoch: "fixture", FenceGeneration: 3, BundleID: "fixture.app", PID: 42, ProcessStartToken: "100:1", WindowID: 17, DisplayID: 1, Width: width, Height: height, Bounds: CaptureBounds{X: -100, Y: 20, Width: float64(width), Height: float64(height)}, Scale: 1, ContentHash: hex.EncodeToString(sum[:]), CapturedAt: now, ExpiresAt: now.Add(WindowFramePermitLifetime)}
		switch f.mode {
		case "wrongOwner":
			permit.Owner.ClientID = "foreign"
		case "wrongHash":
			permit.ContentHash = "bad"
		case "wrongEpoch":
			permit.HelperEpoch = "foreign"
		case "wrongFence":
			permit.FenceGeneration = 4
		case "wrongBirth":
			permit.ProcessStartToken = "100:2"
		case "wrongWindow":
			permit.WindowID = 18
		case "badScale":
			permit.Scale = 2
		case "expired":
			permit.CapturedAt = now.Add(-time.Minute)
			permit.ExpiresAt = permit.CapturedAt.Add(WindowFramePermitLifetime)
		}
		f.permit = permit
		reply.Result, _ = json.Marshal(map[string]any{"permit": permit, "pngBase64": base64.StdEncoding.EncodeToString(buf.Bytes())})
	case "windows.clickFrame":
		if r.Lease == nil || r.Lease.ID != "held" || r.Lease.Generation != 3 {
			panic("click missing retained fence")
		}
		f.clicks++
		var params struct {
			Owner  WindowFrameOwner `json:"owner"`
			ID     string           `json:"permitId"`
			X      int64            `json:"x"`
			Y      int64            `json:"y"`
			Bundle string           `json:"expectedApp"`
			PID    int              `json:"pid"`
			Birth  string           `json:"processStartToken"`
		}
		json.Unmarshal(r.Params, &params)
		if params.Owner != f.owner || params.ID != f.permit.ID || params.Bundle != "fixture.app" || params.PID != 42 || params.Birth != "100:1" {
			panic("click identity changed")
		}
		reply.Receipt = &Receipt{DispatchState: "dispatched", TargetRef: "window:17"}
		proof := map[string]any{"permitId": params.ID, "owner": params.Owner, "pid": 42, "startToken": "100:1", "bundleID": "fixture.app", "windowId": 17, "identity": "window:17", "point": map[string]any{"x": params.X, "y": params.Y}, "requestId": r.RequestID, "observedAt": time.Now(), "businessSuccess": false}
		switch f.mode {
		case "wrongClickOwner":
			proof["owner"] = WindowFrameOwner{Namespace: f.owner.Namespace, ClientID: "foreign", SessionID: f.owner.SessionID}
		case "wrongPoint":
			proof["point"] = map[string]any{"x": 0, "y": 0}
		case "businessClaim":
			proof["businessSuccess"] = true
		case "staleReceipt":
			proof["observedAt"] = time.Now().Add(-time.Minute)
		case "noReceipt":
			reply.Receipt = nil
		case "transport":
			return Reply{}, &TransportError{Cause: context.DeadlineExceeded, DispatchState: "unknown"}
		}
		reply.Result, _ = json.Marshal(proof)
	default:
		panic("unqualified fallback: " + r.Method)
	}
	return reply, nil
}

func frameGatewayFixture(t *testing.T, mode string) (context.Context, auth.Principal, *Gateway, *frameFixture, model.Surface) {
	t.Helper()
	p, _ := auth.NewPrincipal("fixture", "", "frame-owner", []string{"desktop:control", "desktop:observe"})
	p.ClientID = "frame-client"
	ctx := auth.WithConsentBinding(auth.WithPrincipal(context.Background(), p), auth.ConsentBinding{SessionID: "frame-session", GrantID: "grant", Purpose: "Frame click"})
	f := &frameFixture{mode: mode, owner: WindowFrameOwner{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: "frame-session"}}
	g, err := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}, Lease: func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "held", Generation: 3}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, p, g, f, model.Surface{Kind: "native", BundleID: "fixture.app", ProcessID: 42, ProcessStartToken: "100:1"}
}
func frameClickStep(t *testing.T) model.Step {
	t.Helper()
	plan, err := script.Compile(`app("fixture.app",processId:42,processStartToken:"100:1").clickWindowFrame(captureRef:"dedicated-permit",x:3,y:4)`)
	if err != nil {
		t.Fatal(err)
	}
	return plan.Steps[0]
}

func TestWindowFrameCaptureClickRetainsFenceAndBurnsPermitWithoutOutcomePromotion(t *testing.T) {
	ctx, p, g, f, surface := frameGatewayFixture(t, "")
	frame, err := g.CaptureWindowFrame(ctx, p, surface, 17)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame.PNG) == 0 {
		t.Fatal("frame bytes unavailable")
	}
	result, err := g.Execute(ctx, p, frameClickStep(t), nil)
	if err != nil || result.DispatchState != "dispatched" || result.VerificationState != "unknown" || result.Postcondition != nil || f.clicks != 1 {
		t.Fatalf("receipt promoted or click failed: %+v %v", result, err)
	}
	result, err = g.Execute(ctx, p, frameClickStep(t), nil)
	if err == nil || result.DispatchState != "notDispatched" || f.clicks != 1 {
		t.Fatal("permit replay dispatched")
	}
}
func TestWindowFrameCaptureRejectsMalformedQualificationAndEvidence(t *testing.T) {
	for _, mode := range []string{"noCapture", "noOptIn", "wrongOwner", "wrongHash", "wrongEpoch", "wrongFence", "wrongBirth", "wrongWindow", "badScale", "expired"} {
		t.Run(mode, func(t *testing.T) {
			ctx, p, g, f, surface := frameGatewayFixture(t, mode)
			if _, err := g.CaptureWindowFrame(ctx, p, surface, 17); err == nil || f.clicks != 0 {
				t.Fatal("unsafe frame accepted")
			}
		})
	}
}
func TestWindowFrameClickUncertainReceiptNeverReplays(t *testing.T) {
	for _, mode := range []string{"wrongClickOwner", "wrongPoint", "businessClaim", "staleReceipt", "noReceipt", "transport"} {
		t.Run(mode, func(t *testing.T) {
			ctx, p, g, f, surface := frameGatewayFixture(t, mode)
			if _, err := g.CaptureWindowFrame(ctx, p, surface, 17); err != nil {
				t.Fatal(err)
			}
			result, err := g.Execute(ctx, p, frameClickStep(t), nil)
			if err == nil || result.DispatchState != "unknown" || result.VerificationState != "unknown" {
				t.Fatalf("uncertain receipt: %+v %v", result, err)
			}
			if _, err = g.Execute(ctx, p, frameClickStep(t), nil); err == nil || f.clicks != 1 {
				t.Fatal("uncertain mutation replayed")
			}
		})
	}
}
func TestWindowFrameClickCrossClientSessionAndPixelsFailBeforeInput(t *testing.T) {
	for _, mode := range []string{"client", "session", "pixels", "expired", "epoch"} {
		t.Run(mode, func(t *testing.T) {
			ctx, p, g, f, surface := frameGatewayFixture(t, "")
			if _, err := g.CaptureWindowFrame(ctx, p, surface, 17); err != nil {
				t.Fatal(err)
			}
			step := frameClickStep(t)
			switch mode {
			case "client":
				p.ClientID = "foreign"
				ctx = auth.WithPrincipal(ctx, p)
			case "session":
				ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "foreign", Purpose: "Frame click", GrantID: "grant"})
			case "pixels":
				step.Arguments["frameClick"].Object["x"] = model.Value{Kind: model.NumberValue, Number: 16}
			case "expired":
				g.framePermit.ExpiresAt = time.Now().Add(-time.Second)
			case "epoch":
				g.epoch = "restarted"
			}
			result, err := g.Execute(ctx, p, step, nil)
			if err == nil || result.DispatchState != "notDispatched" || f.clicks != 0 {
				t.Fatal("stale/cross-owner/outside permit dispatched")
			}
		})
	}
}

func TestWindowFrameCaptureAcceptsLosslessPNGAboveOrdinaryFrameBound(t *testing.T) {
	ctx, p, g, _, surface := frameGatewayFixture(t, "large")
	frame, err := g.CaptureWindowFrame(ctx, p, surface, 17)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame.PNG) <= MaximumFrameBytes || frame.Permit.Width != 1024 || frame.Permit.Height != 768 {
		t.Fatal("large exact frame scaled or truncated")
	}
	hash := sha256.Sum256(frame.PNG)
	if frame.Permit.ContentHash != hex.EncodeToString(hash[:]) {
		t.Fatal("large frame hash changed")
	}
}
