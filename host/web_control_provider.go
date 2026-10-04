package host

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

// Internal seam for inert lifecycle tests; production always passes h.chrome.
type webControlProviderGateway interface {
	AdmitControlWithStatus(context.Context, auth.Principal, model.Surface) (chrome.ControlAdmission, error)
	PinControlRead(context.Context, auth.Principal, chrome.ControlAuthority) (chrome.ReadBinding, error)
	VerifyControl(context.Context, auth.Principal, chrome.ControlAuthority) error
	ExecuteControl(context.Context, auth.Principal, model.Step, map[string]model.Value, chrome.ControlAuthority) (automation.StepResult, error)
	RetireControl(context.Context, auth.Principal, chrome.ControlAuthority) (bool, error)
	ReadPinned(context.Context, auth.Principal, chrome.ReadBinding, model.Selector, string, map[string]model.Value) (model.Value, chrome.ReadProof, error)
	Close() error
}
type providerAuthority struct {
	authority                   chrome.ControlAuthority
	owned, published, uncertain bool
	reader                      *webPostconditionRead
}

// productionWebControl uses broker-authenticated channel/endpoint evidence.
func (h *Host) productionWebControl() *WebControlOptions {
	return newProductionWebControlProvider(h.chrome, func(ctx context.Context, p auth.Principal) error { return h.markControlCleanupUnknown(ctx, p) },
		func(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value, a chrome.ControlAuthority) (automation.StepResult, error) {
			denied := automation.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
			intent, err := data.RequireCommittedStepIntent(ctx, p)
			if err != nil {
				return denied, err
			}
			if h.durable == nil || p.ClientID == "" || a.MutationFingerprintVersion != 2 || a.Document.MutationFingerprintVersion != 2 {
				return denied, ErrWebControlUnqualified
			}
			attemptID := data.ChromeAttemptBrowserIDV2(p.Namespace, p.ClientID, intent.AttemptID)
			return h.chrome.ExecuteControlBound(ctx, p, step, values, a, attemptID, func(ctx context.Context, p auth.Principal, descriptor chrome.BoundMutation) (chrome.BindingCommit, error) {
				return commitChromeBinding(ctx, p, step, a, descriptor, h.durable.InvokeCommittedComponent)
			})
		})
}

type boundWebExecutor func(context.Context, auth.Principal, model.Step, map[string]model.Value, chrome.ControlAuthority) (automation.StepResult, error)

func newProductionWebControlProvider(gateway webControlProviderGateway, recordUnknown func(context.Context, auth.Principal) error, bound ...boundWebExecutor) *WebControlOptions {
	var mu sync.Mutex
	entries := map[string]providerAuthority{}
	// Only admission/pin/publication owns this lane. Retirement and stop callbacks
	// never wait on it, so a failed pin can retire its own unpublished lease safely.
	admissionLane := make(chan struct{}, 1)
	convert := func(a chrome.ControlAuthority) WebControlAuthority {
		return WebControlAuthority{TrustScope: a.TrustScope, Owner: a.Owner, ExtensionOrigin: a.ExtensionOrigin, Document: a.Document, NativeHost: a.Evidence.NativeHost, BrowserParent: a.Evidence.ChromeParent, BrokerEpoch: a.BrokerEpoch, ChannelEpoch: a.ChannelEpoch, ScopeHash: a.ScopeHash, ID: a.Lease.ID, Generation: a.Lease.Generation}
	}
	lookup := func(a WebControlAuthority) (chrome.ControlAuthority, error) {
		mu.Lock()
		defer mu.Unlock()
		entry, ok := entries[a.ID]
		if !ok || entry.uncertain || !entry.published || convert(entry.authority) != a {
			return chrome.ControlAuthority{}, ErrWebControlUnqualified
		}
		return entry.authority, nil
	}
	uncertain := func(ctx context.Context, p auth.Principal, a chrome.ControlAuthority, cause error) error {
		mu.Lock()
		entry := entries[a.Lease.ID]
		entry.authority = a
		entry.owned = true
		entry.uncertain = true
		entries[a.Lease.ID] = entry
		mu.Unlock()
		bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		return errors.Join(cause, recordUnknown(bounded, p), ErrWebControlCleanupUnknown)
	}
	readiness := func(a chrome.ControlAuthority, reader *webPostconditionRead) WebControlReadiness {
		return WebControlReadiness{ScopeQualified: a.ScopeQualified, postconditionRead: reader, Authority: convert(a), NativeHostSignatureQualified: a.Evidence.KernelPeerQualified, KernelPeerQualified: a.Evidence.KernelPeerQualified, ChromeParentQualified: len(a.Evidence.Ancestors) == 1 && a.Evidence.Ancestors[0] == a.Evidence.ChromeParent, ProfileQualified: a.ProfileQualified, ExtensionQualified: a.ExtensionQualified, DocumentQualified: a.DocumentQualified, ExecutorQualified: a.ExecutorQualified, Actions: []string{"element.press", "element.fill"}, Locators: []string{"role", "id", "testId", "label"}, ValidUntil: time.Now().Add(time.Second)}
	}
	return &WebControlOptions{
		Qualify: func(ctx context.Context, p auth.Principal, surface model.Surface) (WebControlReadiness, error) {
			select {
			case admissionLane <- struct{}{}:
				defer func() { <-admissionLane }()
			case <-ctx.Done():
				return WebControlReadiness{}, ctx.Err()
			}
			admission, err := gateway.AdmitControlWithStatus(ctx, p, surface)
			a := admission.Authority
			mu.Lock()
			existing, known := entries[a.Lease.ID]
			mu.Unlock()
			if err != nil || !admission.Confirmed {
				if admission.Created && a.Lease.ID != "" {
					return WebControlReadiness{}, uncertain(ctx, p, a, errors.Join(err, ErrWebControlUnqualified))
				}
				// A failed requalification does not own or revoke another prepared step.
				return WebControlReadiness{}, errors.Join(err, ErrWebControlUnqualified)
			}
			if known && existing.uncertain {
				return WebControlReadiness{}, ErrWebControlCleanupUnknown
			}
			if known && existing.published {
				if convert(existing.authority) != convert(a) || existing.authority.ClientID != a.ClientID || existing.authority.MutationFingerprintVersion != a.MutationFingerprintVersion {
					return WebControlReadiness{}, ErrWebControlUnqualified
				}
				// Reuse the original immutable pin. A requalification must not replace it
				// or retire an already published authority if a later read-pin probe fails.
				return readiness(a, existing.reader), nil
			}
			owned := admission.Created || (known && existing.owned)
			if !owned {
				return WebControlReadiness{}, errors.New("existing renderer admission is owned outside this provider")
			}
			mu.Lock()
			entries[a.Lease.ID] = providerAuthority{authority: a, owned: true}
			mu.Unlock()
			pin, pinErr := gateway.PinControlRead(ctx, p, a)
			if len(bound) != 0 && (a.MutationFingerprintVersion != 2 || a.Document.MutationFingerprintVersion != 2) {
				pinErr = ErrWebControlUnqualified
			}
			if pinErr != nil {
				cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
				defer cancel()
				type result struct {
					retired bool
					err     error
				}
				done := make(chan result, 1)
				go func() { retired, err := gateway.RetireControl(cleanupCtx, p, a); done <- result{retired, err} }()
				select {
				case outcome := <-done:
					if outcome.err == nil && outcome.retired && cleanupCtx.Err() == nil {
						mu.Lock()
						delete(entries, a.Lease.ID)
						mu.Unlock()
						return WebControlReadiness{}, pinErr
					}
					return WebControlReadiness{}, uncertain(ctx, p, a, errors.Join(pinErr, outcome.err))
				case <-cleanupCtx.Done():
					return WebControlReadiness{}, uncertain(ctx, p, a, errors.Join(pinErr, cleanupCtx.Err()))
				}
			}
			reader := pinnedWebPostconditionReadGateway(gateway, pin)
			mu.Lock()
			entries[a.Lease.ID] = providerAuthority{authority: a, owned: true, published: true, reader: reader}
			mu.Unlock()
			return readiness(a, reader), nil
		},
		VerifyChannel: func(ctx context.Context, p auth.Principal, a WebControlAuthority) error {
			stored, err := lookup(a)
			if err != nil {
				return err
			}
			return gateway.VerifyControl(ctx, p, stored)
		},
		ExecutePinned: func(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value, a WebControlAuthority) (automation.StepResult, error) {
			stored, err := lookup(a)
			if err != nil {
				return automation.StepResult{DispatchState: "notDispatched"}, err
			}
			if len(bound) != 0 {
				if len(bound) != 1 || bound[0] == nil {
					return automation.StepResult{DispatchState: "notDispatched"}, ErrWebControlUnqualified
				}
				return bound[0](ctx, p, step, values, stored)
			}
			return gateway.ExecuteControl(ctx, p, step, values, stored)
		},
		Retire: func(ctx context.Context, p auth.Principal, a WebControlAuthority) (WebControlCleanup, error) {
			stored, err := lookup(a)
			if err != nil {
				return WebControlCleanup{UnknownExecutors: true}, err
			}
			retired, err := gateway.RetireControl(ctx, p, stored)
			if retired && err == nil {
				mu.Lock()
				delete(entries, a.ID)
				mu.Unlock()
			}
			return WebControlCleanup{AuthorityRetired: retired && err == nil, RetiredAuthorityQuiesced: retired && err == nil, UnknownExecutors: !retired || err != nil}, err
		},
		RecordCleanupUnknown: func(ctx context.Context, p auth.Principal, a WebControlAuthority) error { return recordUnknown(ctx, p) },
		Close:                func(context.Context) error { return gateway.Close() },
	}
}

func pinnedWebPostconditionReadGateway(gateway webControlProviderGateway, pin chrome.ReadBinding) *webPostconditionRead {
	return &webPostconditionRead{identity: pin.Identity(), read: func(ctx context.Context, p auth.Principal, target model.Selector, attribute string) (model.Value, chrome.ReadProof, error) {
		return gateway.ReadPinned(ctx, p, pin, target, attribute, nil)
	}}
}
