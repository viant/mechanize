package host

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/engine/durable"
	integration "github.com/viant/mechanize/integration/endly"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/model"
)

func TestCaptureRetainsLeaseThroughSinglePublication(t *testing.T) {
	service, ctx, p, _, options := artifactFixture(t)
	h := &Host{artifacts: service, captureHelper: "fixture-helper", captureMaxBytes: 1024, users: map[string]User{p.Namespace: {NativeBundles: []string{"fixture.app"}}}}
	surface := model.Surface{Kind: "native", BundleID: "fixture.app"}
	releases, consumptions := 0, 0
	releaseBaseline := 0
	options.Consent = func(context.Context, auth.Principal, model.Surface) (*consent.Lease, error) {
		consumptions++
		return nil, errors.New("second consumption forbidden")
	}
	original := options.Publish
	options.Publish = func(ctx context.Context, p auth.Principal, ref data.ArtifactReference) error {
		if releases != 0 {
			t.Fatal("consent released before publication")
		}
		return original(ctx, p, ref)
	}
	h.captureWindow = func(ctx context.Context, options native.WindowCaptureOptions) (native.CapturedImage, error) {
		if options.BundleID != "fixture.app" || options.PID != 42 || options.WindowID != 17 || options.MaxBytes != 1024 || options.HelperPath != "fixture-helper" {
			t.Fatal("capture scope changed")
		}
		if ctx.Err() != nil || releases != releaseBaseline {
			t.Fatal("capture consent unavailable")
		}
		return native.CapturedImage{PNG: []byte("trusted fixture png"), Metadata: native.CaptureMetadata{BundleID: options.BundleID, PID: 42, WindowID: 17, Identity: "window:17", Bytes: 19}}, nil
	}
	ref, image, err := h.captureWindowWithLease(p, surface, 42, 17, &consent.Lease{Context: ctx, Release: func() { releases++ }})
	if err != nil || ref.ID == "" || ref.MediaType != "image/png" || len(image.PNG) == 0 || releases != 1 || consumptions != 0 {
		t.Fatalf("ref=%+v image=%+v err=%v releases=%d consumptions=%d", ref, image.Metadata, err, releases, consumptions)
	}
	if err = service.VerifyArtifact(ctx, p, ref); err != nil {
		t.Fatal(err)
	}
	lost := errors.New("metadata commit acknowledgement unknown")
	options.Publish = func(context.Context, auth.Principal, data.ArtifactReference) error { return lost }
	releaseBaseline = 1
	ref, image, err = h.captureWindowWithLease(p, surface, 42, 17, &consent.Lease{Context: ctx, Release: func() { releases++ }})
	var uncertain *ArtifactPublicationError
	if !errors.As(err, &uncertain) || !errors.Is(err, lost) || ref != uncertain.Reference || len(image.PNG) == 0 || releases != 2 {
		t.Fatalf("ref %+v err %v releases %d", ref, err, releases)
	}
	if err = service.VerifyArtifact(ctx, p, ref); err != nil {
		t.Fatalf("unknown metadata outcome lost immutable bytes: %v", err)
	}
}

func TestCaptureCleanupUncertaintyRetainsConsent(t *testing.T) {
	service, ctx, p, _, _ := artifactFixture(t)
	surface := model.Surface{Kind: "native", BundleID: "fixture.app"}
	for _, confirmed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown", true: "confirmed"}[confirmed], func(t *testing.T) {
			released := 0
			var dispatched context.Context
			h := &Host{artifacts: service, captureHelper: "fixture", captureMaxBytes: 1024, captureWindow: func(ctx context.Context, _ native.WindowCaptureOptions) (native.CapturedImage, error) {
				dispatched = ctx
				return native.CapturedImage{}, &native.CaptureError{Cause: errors.New("transport stopped"), CleanupConfirmed: confirmed, DispatchState: "unknown"}
			}}
			ref, image, err := h.captureWindowWithLease(p, surface, 42, 17, &consent.Lease{Context: ctx, Release: func() { released++ }})
			if err == nil || ref.ID != "" || len(image.PNG) != 0 || dispatched.Err() == nil {
				t.Fatalf("ref %+v err %v", ref, err)
			}
			expected := 0
			if confirmed {
				expected = 1
			}
			if released != expected {
				t.Fatalf("releases=%d", released)
			}
		})
	}
}

func TestCaptureRejectsUnsupportedAndForeignScopes(t *testing.T) {
	service, ctx, p, _, _ := artifactFixture(t)
	h := &Host{artifacts: service, users: map[string]User{p.Namespace: {NativeBundles: []string{"fixture.app"}}}}
	for _, surface := range []model.Surface{{Kind: "web", Origin: "https://fixture.test"}, {Kind: "display"}, {Kind: "native", BundleID: "foreign.app"}, {Kind: "native", BundleID: "fixture.app", Title: "narrower window"}, {Kind: "native", BundleID: "fixture.app"}} {
		if _, _, err := h.CaptureWindow(ctx, p, surface, 42, 17); err == nil {
			t.Fatal("unsupported capture accepted")
		}
	}
	foreign, _ := auth.NewPrincipal("fixture", "tenant", "foreign", []string{"desktop:observe"})
	if _, _, err := h.CaptureWindow(ctx, foreign, model.Surface{Kind: "native", BundleID: "fixture.app"}, 42, 17); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal(err)
	}
	// Caller-provided scopes cannot elevate the verified principal.
	denied := p
	denied.Scopes = nil
	if _, _, err := h.CaptureWindow(auth.WithPrincipal(context.Background(), denied), p, model.Surface{Kind: "native", BundleID: "fixture.app"}, 42, 17); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal(err)
	}
}

func TestCaptureNarrowProcessCannotPublishOtherBirthIdentity(t *testing.T) {
	service, ctx, p, _, options := artifactFixture(t)
	h := &Host{artifacts: service, captureHelper: "fixture", captureMaxBytes: 1024,
		users: map[string]User{p.Namespace: {NativeBundles: []string{"fixture.app"}}}}
	surface := model.Surface{Kind: "native", BundleID: "fixture.app", ProcessID: 42, ProcessStartToken: "123:456"}
	published, released, calls := 0, 0, 0
	options.Publish = func(context.Context, auth.Principal, data.ArtifactReference) error { published++; return nil }
	h.captureWindow = func(_ context.Context, opts native.WindowCaptureOptions) (native.CapturedImage, error) {
		calls++
		if opts.ProcessStartToken != surface.ProcessStartToken || opts.PID != 42 {
			t.Fatal("process narrowing dropped")
		}
		return native.CapturedImage{PNG: []byte("fixture"), Metadata: native.CaptureMetadata{BundleID: "fixture.app", PID: 42, ProcessStartToken: "124:456", WindowID: 17, Identity: "window:17", Bytes: 7}}, nil
	}
	if _, _, err := h.CaptureWindow(ctx, p, surface, 43, 17); err == nil || calls != 0 {
		t.Fatal("mismatched PID reached capture")
	}
	ref, _, err := h.captureWindowWithLease(p, surface, 42, 17, &consent.Lease{Context: ctx, Release: func() { released++ }})
	if err == nil || ref.ID != "" || published != 0 || released != 1 || calls != 1 {
		t.Fatalf("untrusted capture published: ref=%+v err=%v published=%d released=%d calls=%d", ref, err, published, released, calls)
	}
}

// Actual generated consent consumption and publication, with only native bytes
// injected. No helper, TCC, live capture or input is invoked by this fixture.
func TestCaptureOnceGrantDatlyFixture(t *testing.T) {
	service, ctx, p, _, options := artifactFixture(t)
	p.ClientID = "fixture-agent"
	p.ClientName = "Fixture Agent"
	ctx = auth.WithPrincipal(ctx, p)
	_, file, _, _ := runtime.Caller(0)
	source := filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
	builder, err := durable.New(durable.Options{SourceRoot: source, StorageRoot: t.TempDir(), VerifyArtifact: service.VerifyArtifact, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 0, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		return integration.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close(context.Background())
	options.Publish = builder.PublishArtifact
	secondConsumptions := 0
	options.Consent = func(context.Context, auth.Principal, model.Surface) (*consent.Lease, error) {
		secondConsumptions++
		return nil, errors.New("capture must reuse its lease")
	}
	h := &Host{artifacts: service, durable: builder, captureHelper: "fixture", captureMaxBytes: 1024, users: map[string]User{p.Namespace: {NativeBundles: []string{"fixture.app"}}}}
	h.consent, err = NewConsentBroker(ConsentBrokerOptions{Invoke: func(ctx context.Context, p auth.Principal, request exec.ComponentRequest) (any, error) {
		return builder.InvokePrivateComponent(ctx, p, request)
	}, Enrolled: h.enrolled, SessionOwned: func(_ context.Context, _ auth.Principal, id string) error {
		if id != "fixture-session" {
			return auth.ErrUnauthorized
		}
		return nil
	}, Policy: h.ConsentPolicy})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	h.captureWindow = func(_ context.Context, opts native.WindowCaptureOptions) (native.CapturedImage, error) {
		calls++
		return native.CapturedImage{PNG: []byte("trusted fixture png"), Metadata: native.CaptureMetadata{BundleID: opts.BundleID, PID: opts.PID, WindowID: opts.WindowID, Identity: "window:17", Bytes: 19}}, nil
	}
	in := consent.RequestInput{Scope: consent.Scope{Kind: "application", BundleID: "fixture.app"}, Modes: []consent.Mode{consent.Observe}, Purpose: "Inspect fixture capture", DurationSeconds: 60}
	request, err := h.consent.Request(ctx, p, "fixture-session", in)
	if err != nil {
		t.Fatal(err)
	}
	operator := p
	operator.Scopes = append(append([]string(nil), p.Scopes...), "consent:admin")
	human, err := auth.WithNativeHuman(auth.WithPrincipal(ctx, operator))
	if err != nil {
		t.Fatal(err)
	}
	decision, _ := json.Marshal(map[string]any{"requestID": request.ID, "decision": consent.AllowOnce})
	value, err := h.consent.NativeRPC(human, "decide", decision)
	if err != nil {
		t.Fatal(err)
	}
	grant := value.(*consent.Grant)
	ctx = WithConsentBinding(ctx, ConsentBinding{GrantID: grant.ID, SessionID: "fixture-session", Purpose: in.Purpose})
	ref, _, err := h.CaptureWindow(ctx, p, model.Surface{Kind: "native", BundleID: "fixture.app"}, 42, 17)
	if err != nil || ref.ID == "" || calls != 1 || secondConsumptions != 0 {
		t.Fatalf("ref %+v err %v calls %d second %d", ref, err, calls, secondConsumptions)
	}
	if err = builder.PublishArtifact(ctx, p, ref); err != nil {
		t.Fatalf("capture metadata replay: %v", err)
	}
	if _, _, err = h.CaptureWindow(ctx, p, model.Surface{Kind: "native", BundleID: "fixture.app"}, 42, 17); err == nil || calls != 1 {
		t.Fatalf("once replay dispatched: calls %d err %v", calls, err)
	}
}
