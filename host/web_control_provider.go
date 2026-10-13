package host

import (
	"context"
	"errors"
	"fmt"
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
	authority                            chrome.ControlAuthority
	owned, published, uncertain, retired bool
	reader                               *webPostconditionRead
}

// productionWebControl uses broker-authenticated channel/endpoint evidence.
func (h *Host) productionWebControl() *WebControlOptions {
	return newProductionWebControlProvider(h.chrome,
		func(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value, a chrome.ControlAuthority) (automation.StepResult, error) {
			denied := automation.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
			intent, err := data.RequireCommittedStepIntent(ctx, p)
			if err != nil {
				return denied, err
			}
			if h.durable == nil || p.ClientID == "" || a.MutationFingerprintVersion != 2 || a.Document.MutationFingerprintVersion != 2 {
				return denied, ErrWebControlUnqualified
			}
			if step.Action == "browser.navigate" {
				// Redirects may reach any ordinary website; require explicit browser-wide
				// human consent, not an origin-only grant on the source page.
				scope, e := h.operationConsentScope(p, step.Target.Surface)
				if e != nil || !a.AllWebsites || scope.Kind != "browser" {
					return denied, auth.ErrUnauthorized
				}
			}
			attemptID := data.ChromeAttemptBrowserIDV2(p.Namespace, p.ClientID, intent.AttemptID)
			return h.chrome.ExecuteControlBound(ctx, p, step, values, a, attemptID, func(ctx context.Context, p auth.Principal, descriptor chrome.BoundMutation) (chrome.BindingCommit, error) {
				return commitChromeBinding(ctx, p, step, a, descriptor, h.durable.InvokeCommittedComponent)
			})
		})
}

type boundWebExecutor func(context.Context, auth.Principal, model.Step, map[string]model.Value, chrome.ControlAuthority) (automation.StepResult, error)

func newProductionWebControlProvider(gateway webControlProviderGateway, bound ...boundWebExecutor) *WebControlOptions {
	var mu sync.Mutex
	entries := map[string]providerAuthority{}
	// Only admission/pin/publication owns this lane. Retirement and stop callbacks
	// never wait on it, so a failed pin can retire its own unpublished lease safely.
	admissionLane := make(chan struct{}, 1)
	convert := func(a chrome.ControlAuthority) WebControlAuthority {
		return WebControlAuthority{TrustScope: a.TrustScope, Owner: a.Owner, ExtensionOrigin: a.ExtensionOrigin, Document: a.Document, NativeHost: a.Evidence.NativeHost, BrowserParent: a.Evidence.ChromeParent, BrokerEpoch: a.BrokerEpoch, ChannelEpoch: a.ChannelEpoch, ScopeHash: a.ScopeHash, ID: a.Lease.ID, Generation: a.Lease.Generation}
	}
	lookup := func(a WebControlAuthority, retirement bool) (chrome.ControlAuthority, error) {
		mu.Lock()
		defer mu.Unlock()
		entry, ok := entries[a.ID]
		if !ok || !entry.owned || (!retirement && (entry.uncertain || entry.retired || !entry.published)) || convert(entry.authority) != a {
			return chrome.ControlAuthority{}, ErrWebControlUnqualified
		}
		return entry.authority, nil
	}
	uncertain := func(a chrome.ControlAuthority, cause, cleanup error) error {
		mu.Lock()
		entry := entries[a.Lease.ID]
		entry.authority = a
		entry.owned = true
		entry.uncertain = true
		entries[a.Lease.ID] = entry
		mu.Unlock()
		return newWebPreparationCleanupFailure(cause, cleanup)
	}
	retireAuthority := func(ctx context.Context, p auth.Principal, a WebControlAuthority) (WebControlCleanup, error) {
		stored, err := lookup(a, true)
		if err != nil {
			return WebControlCleanup{UnknownExecutors: true}, err
		}
		if stored.Owner != p.Namespace || stored.ClientID != p.ClientID {
			return WebControlCleanup{UnknownExecutors: true}, auth.ErrUnauthorized
		}
		mu.Lock()
		completed := entries[a.ID].retired
		mu.Unlock()
		if completed {
			return WebControlCleanup{AuthorityRetired: true, RetiredAuthorityQuiesced: true}, nil
		}
		retired, err := gateway.RetireControl(ctx, p, stored)
		if retired && err == nil {
			mu.Lock()
			// A concurrent owner may already have consumed completion. Never
			// resurrect it or overwrite a replacement authority after a late ACK.
			if entry, exists := entries[a.ID]; exists && convert(entry.authority) == a {
				entry.retired = true
				entries[a.ID] = entry
			}
			mu.Unlock()
		}
		return WebControlCleanup{AuthorityRetired: retired && err == nil, RetiredAuthorityQuiesced: retired && err == nil, UnknownExecutors: !retired || err != nil}, err
	}
	consumeRetirement := func(p auth.Principal, a WebControlAuthority) {
		mu.Lock()
		defer mu.Unlock()
		entry, exists := entries[a.ID]
		if exists && entry.retired && entry.authority.Owner == p.Namespace && entry.authority.ClientID == p.ClientID && convert(entry.authority) == a {
			delete(entries, a.ID)
		}
	}
	retireUnpublished := func(ctx context.Context, p auth.Principal, a chrome.ControlAuthority, cause error) error {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		type result struct {
			retired bool
			err     error
		}
		done := make(chan result, 1)
		go func() {
			cleanup, err := retireAuthority(cleanupCtx, p, convert(a))
			done <- result{cleanup.AuthorityRetired, err}
		}()
		select {
		case outcome := <-done:
			if outcome.err == nil && outcome.retired && cleanupCtx.Err() == nil {
				consumeRetirement(p, convert(a))
				return cause
			}
			return uncertain(a, cause, errors.Join(outcome.err, cleanupCtx.Err()))
		case <-cleanupCtx.Done():
			return uncertain(a, cause, cleanupCtx.Err())
		}
	}
	readiness := func(a chrome.ControlAuthority, reader *webPostconditionRead) WebControlReadiness {
		actions := []string{"element.press", "element.fill", "browser.activate"}
		if a.SelectOptionVersion == 1 {
			actions = append(actions, "element.select")
		}
		if a.AllWebsites {
			actions = append(actions, "browser.navigate")
		}
		indexed := false
		if qualified, ok := gateway.(interface {
			IndexedControlQualified(chrome.ControlAuthority) bool
		}); ok {
			indexed = qualified.IndexedControlQualified(a)
		}
		return WebControlReadiness{IndexedQueryQualified: indexed, ScopeQualified: a.ScopeQualified, postconditionRead: reader, Authority: convert(a), NativeHostSignatureQualified: a.Evidence.KernelPeerQualified, KernelPeerQualified: a.Evidence.KernelPeerQualified, ChromeParentQualified: len(a.Evidence.Ancestors) == 1 && a.Evidence.Ancestors[0] == a.Evidence.ChromeParent, ProfileQualified: a.ProfileQualified, ExtensionQualified: a.ExtensionQualified, DocumentQualified: a.DocumentQualified, ExecutorQualified: a.ExecutorQualified, Actions: actions, Locators: []string{"role", "id", "testId", "label"}, ValidUntil: time.Now().Add(time.Second)}
	}
	return &WebControlOptions{
		Qualify: func(ctx context.Context, p auth.Principal, surface model.Surface) (WebControlReadiness, error) {
			select {
			case admissionLane <- struct{}{}:
				defer func() { <-admissionLane }()
			case <-ctx.Done():
				return WebControlReadiness{}, ctx.Err()
			}
			// Retry only revocation of retained unpublished admissions before acquiring.
			mu.Lock()
			var retained []chrome.ControlAuthority
			for _, entry := range entries {
				if entry.owned && entry.uncertain && entry.authority.Owner == p.Namespace && entry.authority.ClientID == p.ClientID && webSurfaceMatchesAuthority(surface, convert(entry.authority)) {
					retained = append(retained, entry.authority)
				}
			}
			mu.Unlock()
			recoveryCtx, stopRecovery := context.WithTimeout(ctx, 2*time.Second)
			defer stopRecovery()
			for _, original := range retained {
				cleanup, err := retireAuthority(recoveryCtx, p, convert(original))
				err = errors.Join(err, recoveryCtx.Err())
				if err != nil || !cleanup.AuthorityRetired {
					return WebControlReadiness{}, errors.Join(err, ErrWebControlCleanupUnknown)
				}
				consumeRetirement(p, convert(original))
			}
			admission, err := gateway.AdmitControlWithStatus(ctx, p, surface)
			a := admission.Authority
			mu.Lock()
			existing, known := entries[a.Lease.ID]
			mu.Unlock()
			if err != nil || !admission.Confirmed {
				if admission.Created && a.Lease.ID != "" {
					// This acquisition is ours even if post-ACK verification
					// failed. Try its existing exact retirement path now.
					mu.Lock()
					entries[a.Lease.ID] = providerAuthority{authority: a, owned: true}
					mu.Unlock()
					return WebControlReadiness{}, retireUnpublished(ctx, p, a, errors.Join(err, fmt.Errorf("%w: provider.admission", ErrWebControlUnqualified)))
				}
				// A failed requalification does not own or revoke another prepared step.
				return WebControlReadiness{}, errors.Join(err, fmt.Errorf("%w: provider.admission", ErrWebControlUnqualified))
			}
			if known && existing.uncertain {
				return WebControlReadiness{}, ErrWebControlCleanupUnknown
			}
			if known && existing.published {
				if convert(existing.authority) != convert(a) || existing.authority.ClientID != a.ClientID || existing.authority.MutationFingerprintVersion != a.MutationFingerprintVersion {
					return WebControlReadiness{}, fmt.Errorf("%w: provider.publishedAuthority", ErrWebControlUnqualified)
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
			if pinErr != nil {
				pinErr = errors.Join(pinErr, fmt.Errorf("%w: provider.readPin", ErrWebControlUnqualified))
			}
			if len(bound) != 0 && (a.MutationFingerprintVersion != 2 || a.Document.MutationFingerprintVersion != 2) {
				pinErr = fmt.Errorf("%w: provider.fingerprintNegotiation", ErrWebControlUnqualified)
			}
			if pinErr != nil {
				return WebControlReadiness{}, retireUnpublished(ctx, p, a, pinErr)
			}
			reader := pinnedWebPostconditionReadGateway(gateway, pin)
			mu.Lock()
			entries[a.Lease.ID] = providerAuthority{authority: a, owned: true, published: true, reader: reader}
			mu.Unlock()
			result := readiness(a, reader)
			result.NewlyAcquired = true
			return result, nil
		},
		VerifyChannel: func(ctx context.Context, p auth.Principal, a WebControlAuthority) error {
			stored, err := lookup(a, false)
			if err != nil {
				return err
			}
			return gateway.VerifyControl(ctx, p, stored)
		},
		ExecutePinned: func(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value, a WebControlAuthority) (automation.StepResult, error) {
			stored, err := lookup(a, false)
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
		Retire:         retireAuthority,
		RetireConsumed: consumeRetirement,
		Close: func(ctx context.Context) error {
			select {
			case admissionLane <- struct{}{}:
				defer func() { <-admissionLane }()
			case <-ctx.Done():
				return ctx.Err()
			}
			mu.Lock()
			retained := false
			for _, entry := range entries {
				retained = retained || !entry.retired
			}
			mu.Unlock()
			if retained {
				return ErrWebControlCleanupUnknown
			}
			return gateway.Close()
		},
	}
}

func pinnedWebPostconditionReadGateway(gateway webControlProviderGateway, pin chrome.ReadBinding) *webPostconditionRead {
	return &webPostconditionRead{identity: pin.Identity(), read: func(ctx context.Context, p auth.Principal, target model.Selector, attribute string) (model.Value, chrome.ReadProof, error) {
		return gateway.ReadPinned(ctx, p, pin, target, attribute, nil)
	}}
}
