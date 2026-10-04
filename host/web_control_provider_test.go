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
	retired                       chan struct{}
	acquireAmbiguous              bool
	waitRetire                    bool
}

func (f *providerGatewayFixture) AdmitControlWithStatus(_ context.Context, p auth.Principal, s model.Surface) (chrome.ControlAdmission, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	records := 0
	provider := newProductionWebControlProvider(f, func(context.Context, auth.Principal) error { records++; return nil })
	if _, err := provider.Qualify(ctx, p, s); !errors.Is(err, pinErr) || errors.Is(err, ErrWebControlCleanupUnknown) {
		t.Fatalf("confirmed exact retirement not preserved %v", err)
	}
	if f.held != nil || f.retireCalls != 1 || f.pinCalls != 1 || records != 0 {
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
	provider := newProductionWebControlProvider(f, func(context.Context, auth.Principal) error { return nil })
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
	provider := newProductionWebControlProvider(f, func(context.Context, auth.Principal) error { t.Fatal("foreign owner cleanup recorded"); return nil })
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
			records := 0
			provider := newProductionWebControlProvider(f, func(context.Context, auth.Principal) error { records++; return nil })
			if _, err := provider.Qualify(ctx, p, s); !errors.Is(err, ErrWebControlCleanupUnknown) || records != 1 || f.held == nil {
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
	records := 0
	provider := newProductionWebControlProvider(f, func(context.Context, auth.Principal) error { records++; return nil })
	started := time.Now()
	_, err := provider.Qualify(ctx, p, s)
	if !errors.Is(err, ErrWebControlCleanupUnknown) || !errors.Is(err, context.DeadlineExceeded) || records != 1 || f.held == nil || time.Since(started) > 3*time.Second {
		t.Fatalf("timeout claimed cleanup or blocked indefinitely: %v", err)
	}
}

func TestProductionBoundProviderRequiresV2AndNeverUsesLegacyDispatch(t *testing.T) {
	for _, version := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			ctx, p, s := providerActor(t)
			f := &providerGatewayFixture{fingerprintVersion: version}
			called := 0
			provider := newProductionWebControlProvider(f, func(context.Context, auth.Principal) error { return nil }, func(_ context.Context, actual auth.Principal, _ model.Step, _ map[string]model.Value, a chrome.ControlAuthority) (automation.StepResult, error) {
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
