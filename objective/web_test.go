package objective

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

func webInputs() map[string]model.Value {
	values := map[string]model.Value{}
	for k, v := range map[string]string{"profileChannel": "p1", "browserInstance": "b1", "origin": "https://fixture.test", "documentId": "doc1", "extensionOrigin": "chrome-extension://" + strings.Repeat("a", 32) + "/", "brokerEpoch": "broker-epoch", "channelEpoch": "channel-epoch", "scopeHash": "scope-hash", "strategy": "id", "selector": "result", "attribute": "text", "expected": "ready"} {
		values[k] = model.Value{Kind: model.StringValue, String: v}
	}
	values["tabId"] = model.Value{Kind: model.NumberValue, Number: 7}
	values["frameId"] = model.Value{Kind: model.NumberValue, Number: 0}
	values["documentGeneration"] = model.Value{Kind: model.NumberValue, Number: 1}
	return values
}

func webPinnedIdentity() WebIdentity {
	return WebIdentity{ProfileChannel: "p1", BrowserInstance: "b1", Origin: "https://fixture.test", TabID: 7, FrameID: 0, DocumentID: "doc1", Generation: 1, ExtensionOrigin: "chrome-extension://" + strings.Repeat("a", 32) + "/", BrokerEpoch: "broker-epoch", ChannelEpoch: "channel-epoch", ScopeHash: "scope-hash"}
}
func webAuthoredInputs() map[string]model.Value {
	all := webInputs()
	inputs := map[string]model.Value{}
	for _, key := range []string{"origin", "strategy", "selector", "attribute", "expected"} {
		inputs[key] = all[key]
	}
	return inputs
}

func TestWebPredicateDerivesPrivateIdentityAndAcceptsOnlyExactHints(t *testing.T) {
	ctx, p := webActor(t)
	pinned := webPinnedIdentity()
	resolves, reads := 0, 0
	adapter, err := NewWebWithOptions(WebOptions{ResolveIdentity: func(_ context.Context, actual auth.Principal, origin string) (WebIdentity, error) {
		resolves++
		if actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || origin != pinned.Origin {
			return WebIdentity{}, auth.ErrUnauthorized
		}
		return pinned, nil
	}, Read: func(_ context.Context, actual auth.Principal, target model.Selector, attribute string, id WebIdentity) (model.Value, WebEvidence, error) {
		reads++
		if id != pinned || target.Surface.TabID != "p1/b1/7" || attribute != "text" {
			t.Fatal("derived identity changed original scope")
		}
		id.Generation++
		return model.Value{Kind: model.StringValue, String: "ready"}, WebEvidence{Owner: actual.Namespace, ClientID: actual.ClientID, Identity: id, RequestID: "read", ObservedAt: time.Now()}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, inputs := range []map[string]model.Value{webAuthoredInputs(), webInputs()} {
		result, err := adapter.Evaluate(ctx, p, "valueEquals", inputs)
		if err != nil || result.Truth != True || result.Authority != Observational || RequireBusinessSuccess(result) == nil {
			t.Fatalf("authored predicate failed: %+v %v", result, err)
		}
	}
	if reads != 2 || resolves != 2 {
		t.Fatal("private binding was not resolved for each read")
	}
	for _, key := range []string{"profileChannel", "browserInstance", "origin", "documentId", "extensionOrigin", "brokerEpoch", "channelEpoch", "scopeHash", "tabId", "frameId", "documentGeneration"} {
		t.Run(key, func(t *testing.T) {
			inputs := webAuthoredInputs()
			if key == "tabId" || key == "frameId" || key == "documentGeneration" {
				inputs[key] = model.Value{Kind: model.NumberValue, Number: 8}
			} else {
				inputs[key] = model.Value{Kind: model.StringValue, String: "different"}
			}
			before := reads
			if _, err := adapter.Evaluate(ctx, p, "valueEquals", inputs); err == nil || reads != before {
				t.Fatal("mismatched caller identity reached protected read")
			}
		})
	}
}

func TestWebPredicateResolverUnavailableOrInvalidNeverReads(t *testing.T) {
	ctx, p := webActor(t)
	for _, mode := range []string{"missing capability", "foreign frame", "missing generation", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			reads := 0
			useCtx := ctx
			if mode == "cancelled" {
				var cancel context.CancelFunc
				useCtx, cancel = context.WithCancel(ctx)
				cancel()
			}
			adapter, _ := NewWebWithOptions(WebOptions{ResolveIdentity: func(ctx context.Context, _ auth.Principal, _ string) (WebIdentity, error) {
				if mode == "missing capability" {
					return WebIdentity{}, errors.New("original step capability unavailable")
				}
				id := webPinnedIdentity()
				if mode == "foreign frame" {
					id.FrameID = 1
				}
				if mode == "missing generation" {
					id.Generation = 0
				}
				return id, ctx.Err()
			}, Read: func(context.Context, auth.Principal, model.Selector, string, WebIdentity) (model.Value, WebEvidence, error) {
				reads++
				return model.Value{}, WebEvidence{}, nil
			}})
			if _, err := adapter.Evaluate(useCtx, p, "valueEquals", webAuthoredInputs()); err == nil || reads != 0 {
				t.Fatal("missing or invalid private binding performed read")
			}
		})
	}
	legacy, _ := NewWeb(func(context.Context, auth.Principal, model.Selector, string, WebIdentity) (model.Value, WebEvidence, error) {
		t.Fatal("legacy incomplete input read")
		return model.Value{}, WebEvidence{}, nil
	})
	if _, err := legacy.Evaluate(ctx, p, "valueEquals", webAuthoredInputs()); err == nil {
		t.Fatal("legacy constructor inferred unavailable identity")
	}
}
func webActor(t *testing.T) (context.Context, auth.Principal) {
	t.Helper()
	p, _ := auth.NewPrincipal("fixture", "", "alice", []string{"desktop:observe"})
	p.ClientID = "verified-client"
	return auth.WithPrincipal(context.Background(), p), p
}
func TestWebPredicateIndependentProtectedEvidence(t *testing.T) {
	ctx, p := webActor(t)
	reads := 0
	adapter, _ := NewWeb(func(_ context.Context, actual auth.Principal, target model.Selector, attribute string, id WebIdentity) (model.Value, WebEvidence, error) {
		reads++
		if actual.Namespace != p.Namespace || target.Surface.Origin != id.Origin || target.Surface.TabID != "p1/b1/7" || target.Locator.Strategy != "id" || target.Locator.Value.String != "result" || attribute != "text" || id.DocumentID != "doc1" || id.FrameID != 0 {
			t.Fatal("web target identity broadened")
		}
		id.Generation = 3
		return model.Value{Kind: model.StringValue, String: "ready"}, WebEvidence{Owner: p.Namespace, ClientID: p.ClientID, Identity: id, RequestID: "actual-read-request", ObservedAt: time.Now()}, nil
	})
	evaluator, _ := New(map[string]Enrollment{"web": adapter.Enrollment()})
	predicate := model.Predicate{Kind: "adapter", Adapter: "web", Name: "valueEquals", Inputs: webInputs(), RequiredAuthority: "observational", TimeoutMs: 1000, FreshnessMs: 1000}
	result, err := evaluator.Evaluate(ctx, p, predicate, nil)
	if err != nil || result.Truth != True || result.Authority != Observational || reads != 1 || len(result.Evidence) != 1 || strings.Contains(result.Evidence[0].Reference, "ready") {
		t.Fatalf("web proof failed %+v %v", result, err)
	}
	if RequireBusinessSuccess(result) == nil {
		t.Fatal("DOM equality claimed business success")
	}
}
func TestWebPredicateRejectsUnclosedInputsBeforeRead(t *testing.T) {
	ctx, p := webActor(t)
	reads := 0
	adapter, _ := NewWeb(func(context.Context, auth.Principal, model.Selector, string, WebIdentity) (model.Value, WebEvidence, error) {
		reads++
		return model.Value{}, WebEvidence{}, nil
	})
	for _, change := range []func(map[string]model.Value){
		func(v map[string]model.Value) { delete(v, "documentId") }, func(v map[string]model.Value) { delete(v, "channelEpoch") },
		func(v map[string]model.Value) {
			v["script"] = model.Value{Kind: model.StringValue, String: "return true"}
		},
		func(v map[string]model.Value) { v["frameId"] = model.Value{Kind: model.NumberValue, Number: 1} },
		func(v map[string]model.Value) { v["tabId"] = model.Value{Kind: model.StringValue, String: "7"} },
		func(v map[string]model.Value) { v["strategy"] = model.Value{Kind: model.StringValue, String: "css"} },
		func(v map[string]model.Value) {
			v["attribute"] = model.Value{Kind: model.StringValue, String: "innerHTML"}
		},
		func(v map[string]model.Value) {
			v["origin"] = model.Value{Kind: model.StringValue, String: "https://fixture.test/path"}
		},
		func(v map[string]model.Value) {
			v["expected"] = model.Value{Kind: model.StringValue, String: strings.Repeat("x", 256)}
		},
	} {
		inputs := webInputs()
		change(inputs)
		if _, err := adapter.Evaluate(ctx, p, "valueEquals", inputs); err == nil {
			t.Fatal("unclosed web predicate reached callback")
		}
	}
	if reads != 0 {
		t.Fatal("invalid web inputs performed read")
	}
}
func TestWebPredicateRejectsWrongDocumentRedactionAndWeakEvidence(t *testing.T) {
	ctx, p := webActor(t)
	for _, name := range []string{"owner", "client", "origin", "profile", "browser", "tab", "frame", "document", "generation", "broker", "channel", "scope", "extension", "request", "time", "redacted", "truncated"} {
		t.Run(name, func(t *testing.T) {
			adapter, _ := NewWeb(func(_ context.Context, _ auth.Principal, _ model.Selector, _ string, id WebIdentity) (model.Value, WebEvidence, error) {
				proof := WebEvidence{Owner: p.Namespace, ClientID: p.ClientID, Identity: id, RequestID: "actual-request", ObservedAt: time.Now()}
				value := "ready"
				switch name {
				case "owner":
					proof.Owner = "other"
				case "client":
					proof.ClientID = "other"
				case "origin":
					proof.Identity.Origin = "https://other.test"
				case "profile":
					proof.Identity.ProfileChannel = "p2"
				case "browser":
					proof.Identity.BrowserInstance = "b2"
				case "tab":
					proof.Identity.TabID = 8
				case "frame":
					proof.Identity.FrameID = 1
				case "document":
					proof.Identity.DocumentID = "new-doc"
				case "generation":
					proof.Identity.Generation = 0
				case "broker":
					proof.Identity.BrokerEpoch = "new"
				case "channel":
					proof.Identity.ChannelEpoch = "new"
				case "scope":
					proof.Identity.ScopeHash = "new"
				case "extension":
					proof.Identity.ExtensionOrigin = "other"
				case "request":
					proof.RequestID = ""
				case "time":
					proof.ObservedAt = time.Time{}
				case "redacted":
					value = "[redacted]"
				case "truncated":
					value = strings.Repeat("x", 256)
				}
				return model.Value{Kind: model.StringValue, String: value}, proof, nil
			})
			result, err := adapter.Evaluate(ctx, p, "valueEquals", webInputs())
			if err != nil || result.Truth != Unknown || len(result.Evidence) != 0 {
				t.Fatalf("wrong identity/protected value adopted %+v %v", result, err)
			}
		})
	}
}
