package host

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	create "github.com/viant/mechanize/data/browseractivationbindingcreate"
	get "github.com/viant/mechanize/data/browseractivationbindingget"
	"github.com/viant/mechanize/data/loadplan"
	"github.com/viant/mechanize/data/loadrun"
	"github.com/viant/mechanize/model"
	"github.com/viant/xdatly/handler"
)

func TestActivationBindingRequiresCommitAndExactReadback(t *testing.T) {
	for _, mode := range []string{"success", "commitUnknown", "commitError", "noCompletion", "readError", "changedReadback", "duplicateReadback", "foreignOwner", "changedTarget", "changedAttempt", "changedFingerprint", "revokedIntent"} {
		t.Run(mode, func(t *testing.T) {
			ptr := func(s string) *string { return &s }
			p, _ := auth.NewPrincipal("fixture", "", "activation-binding", []string{"desktop:control"})
			p.ClientID = "client"
			ctx, _ := data.WithScope(auth.WithPrincipal(context.Background(), p), data.Scope{Namespace: p.Namespace, LeaseEpoch: 7})
			attempt := strings.Repeat("a", 64)
			effect := data.ChromeRetirementDigest([]string{"effect", attempt})
			intent := data.CommittedStepIntent{Namespace: p.Namespace, ClientID: p.ClientID, RunID: "run", PlanID: "plan", StepID: "step", AttemptID: attempt, EffectID: effect, LeaseEpoch: 7, RunRevision: 2, SessionID: "session", OperationID: "operation"}
			ctx, revoke, e := data.WithCommittedStepIntent(ctx, p, intent)
			if e != nil {
				t.Fatal(e)
			}
			defer revoke()
			step := model.Step{ID: "step", Action: "browser.activateTab", Target: model.Selector{Surface: model.Surface{Kind: "web", Origin: "https://fixture.test", TabID: "profile/browser/42"}, Cardinality: "one"}, TimeoutMs: 3000, Effect: model.Effect{Class: model.ExternalNonIdempotent, BusinessKey: map[string]model.Value{"origin": {Kind: model.StringValue, String: "https://fixture.test"}, "tab": {Kind: model.StringValue, String: "profile/browser/42"}, "request": {Kind: model.StringValue, String: "explicit-request"}}}}
			business, _ := json.Marshal(step.Effect.BusinessKey)
			binding := chrome.ActivationBinding{Namespace: p.Namespace, ClientID: p.ClientID, Origin: step.Target.Surface.Origin, ProfileChannel: "profile", BrowserInstance: "browser", TabID: 42, ChromePID: 101, ChromeStartToken: "100:1", NativeHostPID: 102, NativeHostStartToken: "100:2", BrokerEpoch: "broker", ChannelEpoch: "channel", ScopeHash: strings.Repeat("b", 64), BrowserAttemptID: data.ChromeAttemptBrowserIDV2(p.Namespace, p.ClientID, attempt), FingerprintVersion: 1}
			binding.FingerprintSHA256 = data.BrowserActivationFingerprint(data.BrowserActivationBindingAuthority{ProfileChannel: binding.ProfileChannel, BrowserInstance: binding.BrowserInstance, TabID: binding.TabID, Origin: binding.Origin, BrowserAttemptID: binding.BrowserAttemptID, BrokerEpoch: binding.BrokerEpoch, ChannelEpoch: binding.ChannelEpoch, ScopeHash: binding.ScopeHash})
			switch mode {
			case "foreignOwner":
				binding.ClientID = "other"
			case "changedTarget":
				binding.TabID = 43
			case "changedAttempt":
				binding.BrowserAttemptID = strings.Repeat("c", 64)
			case "changedFingerprint":
				binding.FingerprintSHA256 = strings.Repeat("c", 64)
			case "revokedIntent":
				revoke()
			}
			var saved *create.Binding
			writes, reads := 0, 0
			invoke := func(c context.Context, _ auth.Principal, r exec.ComponentRequest) (any, error) {
				switch r.Target.Component.Name {
				case "LoadPlan":
					return &loadplan.LoadPlanOutput{Data: []*loadplan.PlanRevision{{ContentHash: ptr(strings.Repeat("d", 64))}}}, nil
				case "LoadRun":
					rev := 1
					return &loadrun.LoadRunOutput{Data: []*loadrun.Run{{Effects: []*loadrun.Effect{{Id: ptr(effect), AttemptId: ptr(attempt), State: ptr("intent"), Revision: &rev, BusinessKey: ptr(string(business))}}}}}, nil
				case "CreateBrowserActivationBinding":
					writes++
					if _, e := data.RequireBrowserActivationBindingAuthority(c); e != nil {
						t.Fatal(e)
					}
					saved = r.Input.(*create.CreateBrowserActivationBindingInput).CreateBrowserActivationBinding[0]
					if saved.Has == nil || !saved.Has.StepIndex || !saved.Has.ChannelOperationEpoch {
						t.Fatal("required scalar presence omitted")
					}
					if mode == "commitError" {
						return nil, errors.New("fixture write failed")
					}
					if mode != "noCompletion" {
						state := handler.TransactionCommitted
						if mode == "commitUnknown" {
							state = handler.TransactionCommitUnknown
						}
						r.Completion(handler.Outcome{Transactions: []handler.TransactionOutcome{{State: state}}})
					}
					return &create.CreateBrowserActivationBindingOutput{}, nil
				case "LoadBrowserActivationBinding":
					reads++
					if mode == "readError" {
						return nil, errors.New("fixture read failed")
					}
					raw, _ := json.Marshal(saved)
					row := &get.Binding{}
					if json.Unmarshal(raw, row) != nil {
						t.Fatal("fixture readback")
					}
					if mode == "changedReadback" {
						row.ChromeStartToken = ptr("other-birth")
					}
					rows := []*get.Binding{row}
					if mode == "duplicateReadback" {
						rows = append(rows, row)
					}
					return &get.LoadBrowserActivationBindingOutput{Data: rows}, nil
				}
				t.Fatal("unexpected component", r.Target.Component.Name)
				return nil, nil
			}
			e = commitActivationBinding(ctx, p, step, binding, invoke)
			inputCalls := 0
			if e == nil {
				inputCalls++
			}
			if mode == "success" {
				if e != nil || inputCalls != 1 || writes != 1 || reads != 1 {
					t.Fatal("confirmed binding refused", e, writes, reads)
				}
			} else if e == nil || inputCalls != 0 {
				t.Fatal("unconfirmed binding permitted input", mode)
			}
			if (mode == "commitUnknown" || mode == "commitError" || mode == "noCompletion") && reads != 0 {
				t.Fatal("unconfirmed write accepted by readback")
			}
		})
	}
}
