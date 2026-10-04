package host

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
)

func webObjectiveFixture(t *testing.T) (*Host, *webControlFixture, *int) {
	t.Helper()
	f := newWebControlFixture(t)
	reads := new(int)
	a := f.ready.Authority
	identity := chrome.ReadProof{Owner: f.principal.Namespace, ClientID: f.principal.ClientID, ExtensionOrigin: a.ExtensionOrigin, BrokerEpoch: a.BrokerEpoch, ChannelEpoch: a.ChannelEpoch, ScopeHash: a.ScopeHash, Document: a.Document}
	reader := &webPostconditionRead{identity: identity, read: func(_ context.Context, p auth.Principal, target model.Selector, attribute string) (model.Value, chrome.ReadProof, error) {
		*reads++
		if p.Namespace != f.principal.Namespace || target.Surface.Origin != a.Document.Origin || target.Surface.TabID != a.Document.QualifiedTabID() || attribute != "text" {
			return model.Value{}, chrome.ReadProof{}, auth.ErrUnauthorized
		}
		proof := identity
		proof.RequestID = "actual-protected-read"
		proof.StartedAt = time.Now()
		proof.ReturnedAt = time.Now()
		proof.Document.Generation++
		return model.Value{Kind: model.StringValue, String: "ready"}, proof, nil
	}}
	f.ready.postconditionRead = reader
	f.manager.options.authorizeRead = func(ctx context.Context, p auth.Principal, s model.Surface) (*consent.Lease, error) {
		if s.Kind != "web" || s.Origin != a.Document.Origin {
			return nil, auth.ErrUnauthorized
		}
		return &consent.Lease{Context: ctx, Release: func() { f.releases++ }}, nil
	}
	h := &Host{chrome: &chrome.Gateway{}, webControl: f.manager, users: map[string]User{f.principal.Namespace: {WebOrigins: []string{a.Document.Origin}}}}
	return h, f, reads
}
func webObjectivePredicate(identity objective.WebIdentity) model.Predicate {
	inputs := map[string]model.Value{}
	for key, value := range map[string]string{"profileChannel": identity.ProfileChannel, "browserInstance": identity.BrowserInstance, "origin": identity.Origin, "documentId": identity.DocumentID, "extensionOrigin": identity.ExtensionOrigin, "brokerEpoch": identity.BrokerEpoch, "channelEpoch": identity.ChannelEpoch, "scopeHash": identity.ScopeHash, "strategy": "id", "selector": "result", "attribute": "text", "expected": "ready"} {
		inputs[key] = model.Value{Kind: model.StringValue, String: value}
	}
	inputs["tabId"] = model.Value{Kind: model.NumberValue, Number: int64(identity.TabID)}
	inputs["frameId"] = model.Value{Kind: model.NumberValue, Number: int64(identity.FrameID)}
	inputs["documentGeneration"] = model.Value{Kind: model.NumberValue, Number: int64(identity.Generation)}
	return model.Predicate{Kind: "adapter", Adapter: "web", Name: "valueEquals", Inputs: inputs, Scope: model.PredicateScope{SurfaceRef: "web"}, TimeoutMs: 1000, FreshnessMs: 1000, RequiredAuthority: "observational"}
}
func TestHostWebPostconditionRetainsPreparedDocumentAfterRetirement(t *testing.T) {
	h, f, reads := webObjectiveFixture(t)
	evaluator, err := h.nativeObjective(Config{})
	if err != nil || evaluator == nil {
		t.Fatalf("web evaluator coupled to native availability: %v", err)
	}
	withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
		prepared := prepareWeb(t, f, ctx, p, step)
		identity := webIdentity(f.ready.postconditionRead.identity)
		predicate := webObjectivePredicate(identity)
		before, err := evaluator.Evaluate(prepared, p, predicate, nil)
		if err != nil || before.Truth != objective.Unknown || *reads != 0 {
			t.Fatal("pre-dispatch context provided postcondition proof")
		}
		dispatched, err := f.manager.Execute(prepared, p, step, nil)
		if err != nil || dispatched.DispatchState != "dispatched" || dispatched.VerificationState != "unknown" {
			t.Fatalf("receipt bypassed independent read: %+v %v", dispatched, err)
		}
		verified, err := evaluator.Evaluate(prepared, p, predicate, nil)
		if err != nil || verified.Truth != objective.True || verified.Authority != objective.Observational || *reads != 1 || len(verified.Evidence) != 1 {
			t.Fatalf("same prepared context lost independent proof %+v %v", verified, err)
		}
		if objective.RequireBusinessSuccess(verified) == nil {
			t.Fatal("DOM postcondition became business success")
		}
		if _, err := f.manager.Execute(prepared, p, step, nil); !errors.Is(err, ErrWebControlIntent) {
			t.Fatal("postcondition read enabled action replay")
		}
		if f.dispatches != 1 {
			t.Fatal("independent read replayed original effect")
		}
	})
}
func TestHostWebPostconditionRejectsChangedBindingActorAndReceipt(t *testing.T) {
	for _, name := range []string{"document", "epoch", "origin", "actor", "unprepared", "actual-document", "actual-epoch", "actual-actor", "protected", "cleanup-unknown"} {
		t.Run(name, func(t *testing.T) {
			h, f, reads := webObjectiveFixture(t)
			withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
				prepared := prepareWeb(t, f, ctx, p, step)
				if name == "cleanup-unknown" {
					f.cleanup = WebControlCleanup{UnknownExecutors: true}
				}
				_, _ = f.manager.Execute(prepared, p, step, nil)
				expected := webIdentity(f.ready.postconditionRead.identity)
				target := model.Selector{Surface: model.Surface{Kind: "web", Origin: expected.Origin, TabID: f.ready.Authority.Document.QualifiedTabID()}, Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "result"}, Exact: true}, Cardinality: "one"}
				useCtx := prepared
				usePrincipal := p
				switch name {
				case "document":
					expected.DocumentID = "replacement"
				case "epoch":
					expected.ChannelEpoch = "replacement"
				case "origin":
					expected.Origin = "https://other.test"
					target.Surface.Origin = expected.Origin
				case "actor":
					usePrincipal.ClientID = "other-client"
					useCtx = auth.WithPrincipal(prepared, usePrincipal)
				case "unprepared":
					useCtx = ctx
				}
				if name == "actual-document" || name == "actual-epoch" || name == "actual-actor" || name == "protected" {
					original := f.ready.postconditionRead.read
					f.ready.postconditionRead.read = func(ctx context.Context, p auth.Principal, t model.Selector, a string) (model.Value, chrome.ReadProof, error) {
						value, proof, err := original(ctx, p, t, a)
						switch name {
						case "actual-document":
							proof.Document.DocumentID = "replacement"
						case "actual-epoch":
							proof.ChannelEpoch = "replacement"
						case "actual-actor":
							proof.ClientID = "other-client"
						case "protected":
							value.String = "[redacted]"
						}
						return value, proof, err
					}
				}
				adapter, _ := objective.NewWeb(h.readWebPredicate)
				predicate := webObjectivePredicate(expected)
				evaluator, _ := objective.New(map[string]objective.Enrollment{"web": adapter.Enrollment()})
				result, err := evaluator.Evaluate(useCtx, usePrincipal, predicate, nil)
				if err != nil {
					if name != "actor" {
						t.Fatal(err)
					}
				} else if result.Truth != objective.Unknown || len(result.Evidence) != 0 {
					t.Fatalf("changed/protected source became proof %+v", result)
				}
				if name == "document" || name == "epoch" || name == "origin" || name == "actor" || name == "unprepared" || name == "cleanup-unknown" {
					if *reads != 0 {
						t.Fatal("untrusted context performed read")
					}
				}
				if f.dispatches != 1 {
					t.Fatal("invalid postcondition changed original dispatch count")
				}
			})
		})
	}
}
func TestWebRegistryPreservesNativeAndDoesNotInventMissingBackends(t *testing.T) {
	h := &Host{}
	evaluator, err := h.nativeObjective(Config{})
	if err != nil || evaluator != nil {
		t.Fatal("absent backends created evaluator")
	}
	evaluator, err = h.nativeObjective(Config{NativeLaunch: &NativeLaunchConfig{Mode: "semantic"}})
	if err != nil || evaluator == nil {
		t.Fatal("native adapter registration disappeared")
	}
	ctx, p := reconciliationActor(t)
	result, err := evaluator.Evaluate(ctx, p, model.Predicate{Kind: "adapter", Adapter: "web", Name: "valueEquals", RequiredAuthority: "observational", TimeoutMs: 1000, FreshnessMs: 1000}, nil)
	if err != nil || result.Truth != objective.Unknown {
		t.Fatal("missing web backend qualified an adapter")
	}
}

func authoredWebObjectivePredicate(identity objective.WebIdentity) model.Predicate {
	predicate := webObjectivePredicate(identity)
	for _, key := range []string{"profileChannel", "browserInstance", "tabId", "frameId", "documentId", "documentGeneration", "extensionOrigin", "brokerEpoch", "channelEpoch", "scopeHash"} {
		delete(predicate.Inputs, key)
	}
	return predicate
}

func TestHostAuthoredWebPostconditionUsesOnlyOriginalRetiredPin(t *testing.T) {
	h, f, reads := webObjectiveFixture(t)
	evaluator, err := h.nativeObjective(Config{})
	if err != nil {
		t.Fatal(err)
	}
	withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
		prepared := prepareWeb(t, f, ctx, p, step)
		predicate := authoredWebObjectivePredicate(webIdentity(f.ready.postconditionRead.identity))
		for _, unready := range []context.Context{ctx, prepared} {
			result, err := evaluator.Evaluate(unready, p, predicate, nil)
			if err != nil || result.Truth != objective.Unknown || *reads != 0 {
				t.Fatal("standalone/precondition context obtained private postcondition read")
			}
		}
		if _, err := f.manager.Execute(prepared, p, step, nil); err != nil {
			t.Fatal(err)
		}
		result, err := evaluator.Evaluate(prepared, p, predicate, nil)
		if err != nil || result.Truth != objective.True || result.Authority != objective.Observational || *reads != 1 || f.dispatches != 1 || objective.RequireBusinessSuccess(result) == nil {
			t.Fatalf("authored pinned postcondition: %+v %v reads=%d", result, err, *reads)
		}
		if _, err := f.manager.Execute(prepared, p, step, nil); !errors.Is(err, ErrWebControlIntent) {
			t.Fatal("derived identity enabled replay")
		}
	})
}

func TestHostAuthoredWebPostconditionRejectsHintsAndUnavailableOriginalContext(t *testing.T) {
	for _, mode := range []string{"documentId", "channelEpoch", "scopeHash", "tabId", "frameId", "documentGeneration", "origin", "actor", "consent", "execution", "cleanup", "actual document", "actual epoch", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			h, f, reads := webObjectiveFixture(t)
			evaluator, _ := h.nativeObjective(Config{})
			withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
				prepared := prepareWeb(t, f, ctx, p, step)
				if mode == "cleanup" {
					f.cleanup = WebControlCleanup{UnknownExecutors: true}
				}
				_, _ = f.manager.Execute(prepared, p, step, nil)
				predicate := authoredWebObjectivePredicate(webIdentity(f.ready.postconditionRead.identity))
				useCtx, usePrincipal := prepared, p
				switch mode {
				case "documentId", "channelEpoch", "scopeHash":
					predicate.Inputs[mode] = model.Value{Kind: model.StringValue, String: "different"}
				case "tabId", "frameId", "documentGeneration":
					predicate.Inputs[mode] = model.Value{Kind: model.NumberValue, Number: 99}
				case "origin":
					predicate.Inputs[mode] = model.Value{Kind: model.StringValue, String: "https://other.test"}
				case "actor":
					usePrincipal.ClientID = "different"
					useCtx = auth.WithPrincipal(prepared, usePrincipal)
				case "consent":
					useCtx = auth.WithConsentBinding(prepared, auth.ConsentBinding{SessionID: "different-session", Purpose: "different-purpose"})
				case "execution":
					// Preserve the private pin while breaking its exact operation
					// metadata binding; no public metadata can replace that intent.
					changed := *prepared.Value(webControlIntentKey{}).(*webControlIntent)
					changed.metadata.StepIndex++
					useCtx = context.WithValue(prepared, webControlIntentKey{}, &changed)
				case "cancelled":
					var cancel context.CancelFunc
					useCtx, cancel = context.WithCancel(prepared)
					cancel()
				case "actual document", "actual epoch":
					original := f.ready.postconditionRead.read
					f.ready.postconditionRead.read = func(ctx context.Context, p auth.Principal, target model.Selector, attribute string) (model.Value, chrome.ReadProof, error) {
						value, proof, err := original(ctx, p, target, attribute)
						if mode == "actual document" {
							proof.Document.DocumentID = "replacement-same-origin"
						} else {
							proof.ChannelEpoch = "replacement"
						}
						return value, proof, err
					}
				}
				result, err := evaluator.Evaluate(useCtx, usePrincipal, predicate, nil)
				if err != nil || result.Truth != objective.Unknown || len(result.Evidence) != 0 {
					t.Fatalf("changed context produced evidence: %+v %v", result, err)
				}
				if mode != "actual document" && mode != "actual epoch" && *reads != 0 {
					t.Fatal("caller hints or unavailable context performed a read")
				}
				if f.dispatches != 1 {
					t.Fatal("postcondition reselected or redispatched action")
				}
			})
		})
	}
}
