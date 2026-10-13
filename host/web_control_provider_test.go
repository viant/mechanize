package host

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

type providerGatewayFixture struct {
	mu                            sync.Mutex
	held                          *chrome.ControlAuthority
	next                          int
	fingerprintVersion            int
	pinErr, acquireErr, retireErr error
	pinCalls, retireCalls         int
	acquireCalls                  int
	acquireNotInstalled           bool
	retired                       chan struct{}
	acquireAmbiguous              bool
	waitRetire                    bool
}

func (f *providerGatewayFixture) AdmitControlWithStatus(_ context.Context, p auth.Principal, s model.Surface) (chrome.ControlAdmission, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acquireCalls++
	if f.acquireNotInstalled {
		// Models the backend contract only after its authenticated no-install
		// proof has rolled back the exact new host reservation.
		return chrome.ControlAdmission{}, f.acquireErr
	}
	created := f.held == nil
	if created {
		f.next++
		f.held = &chrome.ControlAuthority{MutationFingerprintVersion: f.fingerprintVersion, Owner: p.Namespace, ClientID: p.ClientID, Document: chrome.Document{MutationFingerprintVersion: f.fingerprintVersion, Identity: chrome.Identity{ProfileChannel: "fixture", BrowserInstance: "browser", TabID: 7, DocumentID: "doc", Generation: 1}, Origin: s.Origin}, Lease: chrome.Lease{ID: "lease", Generation: uint64(f.next)}}
	}
	outcome := chrome.ControlAdmission{Authority: *f.held, Created: created, Confirmed: !f.acquireAmbiguous}
	return outcome, f.acquireErr
}
func (f *providerGatewayFixture) PinControlRead(context.Context, auth.Principal, chrome.ControlAuthority) (chrome.ReadBinding, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pinCalls++
	return chrome.ReadBinding{}, f.pinErr
}
func (f *providerGatewayFixture) VerifyControl(_ context.Context, _ auth.Principal, a chrome.ControlAuthority) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.held == nil || f.held.Lease != a.Lease {
		return errors.New("fixture lease retired")
	}
	return nil
}
func (f *providerGatewayFixture) ExecuteControl(context.Context, auth.Principal, model.Step, map[string]model.Value, chrome.ControlAuthority) (automation.StepResult, error) {
	return automation.StepResult{}, errors.New("fixture forbids input")
}
func (f *providerGatewayFixture) RetireControl(ctx context.Context, _ auth.Principal, a chrome.ControlAuthority) (bool, error) {
	f.mu.Lock()
	f.retireCalls++
	wait := f.waitRetire
	err := f.retireErr
	f.mu.Unlock()
	if wait {
		<-ctx.Done()
		return false, ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		return false, err
	}
	if f.held == nil || f.held.Lease != a.Lease {
		return false, errors.New("fixture exact lease changed")
	}
	f.held = nil
	return true, nil
}
func (f *providerGatewayFixture) ReadPinned(context.Context, auth.Principal, chrome.ReadBinding, model.Selector, string, map[string]model.Value) (model.Value, chrome.ReadProof, error) {
	return model.Value{}, chrome.ReadProof{}, errors.New("fixture forbids read")
}
func (f *providerGatewayFixture) Close() error { return nil }
func providerActor(t *testing.T) (context.Context, auth.Principal, model.Surface) {
	t.Helper()
	p, _ := auth.NewPrincipal("fixture", "", "provider-owner", []string{"desktop:control"})
	p.ClientID = "fixture-client"
	return auth.WithPrincipal(context.Background(), p), p, model.Surface{Kind: "web", Origin: "https://fixture.test"}
}

func TestProductionProviderRetiresOnlyNewUnpublishedPinFailure(t *testing.T) {
	ctx, p, s := providerActor(t)
	pinErr := errors.New("pin unavailable")
	f := &providerGatewayFixture{pinErr: pinErr}
	provider := newProductionWebControlProvider(f)
	if _, err := provider.Qualify(ctx, p, s); !errors.Is(err, pinErr) || errors.Is(err, ErrWebControlCleanupUnknown) {
		t.Fatalf("confirmed exact retirement not preserved %v", err)
	}
	if f.held != nil || f.retireCalls != 1 || f.pinCalls != 1 {
		t.Fatal("new failed pin stranded renderer authority")
	}
	// Confirmed cleanup permits a new admission rather than a map-only reset.
	f.pinErr = nil
	if _, err := provider.Qualify(ctx, p, s); err != nil || f.next != 2 {
		t.Fatalf("new actual admission unavailable %v", err)
	}
}
func TestProductionProviderKeepsPublishedPinOnRequalification(t *testing.T) {
	ctx, p, s := providerActor(t)
	f := &providerGatewayFixture{}
	provider := newProductionWebControlProvider(f)
	first, err := provider.Qualify(ctx, p, s)
	if err != nil {
		t.Fatal(err)
	}
	f.pinErr = errors.New("later pin probe would fail")
	again, err := provider.Qualify(ctx, p, s)
	if err != nil || again.Authority != first.Authority || again.postconditionRead != first.postconditionRead || f.pinCalls != 1 || f.retireCalls != 0 || f.held == nil {
		t.Fatalf("requalification replaced or revoked prepared authority %v", err)
	}
	f.acquireErr = errors.New("requalification failed")
	if _, err := provider.Qualify(ctx, p, s); err == nil || f.retireCalls != 0 || f.held == nil {
		t.Fatal("failed requalification retired original authority")
	}
	f.acquireErr = nil
	if err := provider.VerifyChannel(ctx, p, first.Authority); err != nil {
		t.Fatal("original published authority lost")
	}
}
func TestProductionProviderDoesNotOwnUntrackedReusedAdmission(t *testing.T) {
	ctx, p, s := providerActor(t)
	f := &providerGatewayFixture{pinErr: errors.New("pin failed")}
	original, err := f.AdmitControlWithStatus(ctx, p, s)
	if err != nil {
		t.Fatal(err)
	}
	provider := newProductionWebControlProvider(f)
	if _, err := provider.Qualify(ctx, p, s); err == nil || f.pinCalls != 0 || f.retireCalls != 0 || f.held == nil || f.held.Lease != original.Authority.Lease {
		t.Fatal("provider retired or borrowed someone else's admitted lease")
	}
}
func TestProductionProviderRetainsAmbiguousAcquireAndCleanup(t *testing.T) {
	ctx, p, s := providerActor(t)
	for _, name := range []string{"acquire", "retire"} {
		t.Run(name, func(t *testing.T) {
			f := &providerGatewayFixture{}
			if name == "acquire" {
				f.acquireAmbiguous = true
				f.acquireErr = errors.New("acquire acknowledgement lost")
			} else {
				f.pinErr = errors.New("pin failed")
				f.retireErr = errors.New("retirement unconfirmed")
			}
			provider := newProductionWebControlProvider(f)
			if _, err := provider.Qualify(ctx, p, s); !errors.Is(err, ErrWebControlCleanupUnknown) || f.held == nil {
				t.Fatalf("uncertainty discarded %v", err)
			}
			if name == "acquire" && (f.pinCalls != 0 || f.retireCalls != 0) {
				t.Fatal("ambiguous acquire claimed safe cleanup")
			}
			f.acquireAmbiguous = false
			f.acquireErr = nil
			f.pinErr = nil
			f.retireErr = nil
			if _, err := provider.Qualify(ctx, p, s); !errors.Is(err, ErrWebControlCleanupUnknown) {
				t.Fatal("retained uncertainty automatically became readiness")
			}
		})
	}
}
func TestProductionProviderPinFailureRetirementTimeoutIsUnknown(t *testing.T) {
	ctx, p, s := providerActor(t)
	f := &providerGatewayFixture{pinErr: errors.New("pin failed"), waitRetire: true}
	provider := newProductionWebControlProvider(f)
	started := time.Now()
	_, err := provider.Qualify(ctx, p, s)
	if !errors.Is(err, ErrWebControlCleanupUnknown) || !errors.Is(err, context.DeadlineExceeded) || f.held == nil || time.Since(started) > 3*time.Second {
		t.Fatalf("timeout claimed cleanup or blocked indefinitely: %v", err)
	}
}

func TestProductionBoundProviderRequiresV2AndNeverUsesLegacyDispatch(t *testing.T) {
	for _, version := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			ctx, p, s := providerActor(t)
			f := &providerGatewayFixture{fingerprintVersion: version}
			called := 0
			provider := newProductionWebControlProvider(f, func(_ context.Context, actual auth.Principal, _ model.Step, _ map[string]model.Value, a chrome.ControlAuthority) (automation.StepResult, error) {
				called++
				if actual.ClientID != p.ClientID || a.MutationFingerprintVersion != 2 || a.Document.MutationFingerprintVersion != 2 {
					t.Fatal("wrong pinned v2 authority")
				}
				return automation.StepResult{DispatchState: "notDispatched"}, nil
			})
			ready, err := provider.Qualify(ctx, p, s)
			if version != 2 {
				if !errors.Is(err, ErrWebControlUnqualified) || f.retireCalls != 1 || f.held != nil || called != 0 {
					t.Fatalf("legacy authority accepted or stranded: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = provider.ExecutePinned(ctx, p, model.Step{}, nil, ready.Authority); err != nil || called != 1 {
				t.Fatalf("bound path not called: %v calls=%d", err, called)
			}
		})
	}
}

// The provider consumes the backend's ownership result, not renderer error text.
// Authenticated no-install proof and exact rollback are tested by Chrome itself.
func TestProductionProviderKnownNoInstallAdmissionDoesNotBecomeDispatchUncertainty(t *testing.T) {
	ctx, p, s := providerActor(t)
	rejected := &model.MechanizeError{Code: "staleGeneration", Message: "Renderer generation changed", DispatchState: "notDispatched"}
	f := &providerGatewayFixture{acquireNotInstalled: true, acquireErr: rejected}
	provider := newProductionWebControlProvider(f)
	ready, err := provider.Qualify(ctx, p, s)
	if !errors.Is(err, rejected) || !errors.Is(err, ErrWebControlUnqualified) || errors.Is(err, ErrWebControlCleanupUnknown) || ready.Authority.ID != "" {
		t.Fatalf("known rejected acquisition became dispatch uncertainty/readiness: %+v %v", ready, err)
	}
	if f.pinCalls != 0 || f.retireCalls != 0 || f.acquireCalls != 1 || f.held != nil || f.next != 0 {
		t.Fatal("known no-install admission recorded uncertainty, pinned, retired, or replayed")
	}
	// A subsequent explicit qualification may install a fresh authority; the
	// previous failed call must not leave a provider-side uncertain entry.
	f.acquireNotInstalled = false
	f.acquireErr = nil
	ready, err = provider.Qualify(ctx, p, s)
	if err != nil || ready.Authority.ID == "" || f.held == nil || f.acquireCalls != 2 || f.next != 1 || f.pinCalls != 1 || f.retireCalls != 0 {
		t.Fatalf("fresh qualification blocked by no-install rejection: %+v %v", ready, err)
	}
	if err = provider.VerifyChannel(ctx, p, ready.Authority); err != nil {
		t.Fatal("fresh authority was not published", err)
	}
}

func TestProductionProviderMarksOnlyFirstPublicationNewlyAcquired(t *testing.T) {
	ctx, p, s := providerActor(t)
	f := &providerGatewayFixture{}
	provider := newProductionWebControlProvider(f)
	first, e := provider.Qualify(ctx, p, s)
	if e != nil || !first.NewlyAcquired {
		t.Fatal("fresh ownership missing", e)
	}
	next, e := provider.Qualify(ctx, p, s)
	if e != nil || next.NewlyAcquired || next.Authority != first.Authority || f.retireCalls != 0 {
		t.Fatal("published pin falsely transferred", e)
	}
	if _, e = provider.Retire(ctx, p, first.Authority); e != nil {
		t.Fatal(e)
	}
	fresh, e := provider.Qualify(ctx, p, s)
	if e != nil || !fresh.NewlyAcquired || fresh.Authority.Generation <= first.Authority.Generation {
		t.Fatal("fresh ownership not restored", e)
	}
}

func TestProductionProviderCloseRefusesRetainedAuthority(t *testing.T) {
	ctx, p, s := providerActor(t)
	f := &providerGatewayFixture{}
	provider := newProductionWebControlProvider(f)
	ready, e := provider.Qualify(ctx, p, s)
	if e != nil {
		t.Fatal(e)
	}
	if e = provider.Close(ctx); !errors.Is(e, ErrWebControlCleanupUnknown) || f.held == nil {
		t.Fatal("provider closed a retained pin", e)
	}
	if _, e = provider.Retire(ctx, p, ready.Authority); e != nil {
		t.Fatal(e)
	}
	if e = provider.Close(ctx); e != nil {
		t.Fatal(e)
	}
}
