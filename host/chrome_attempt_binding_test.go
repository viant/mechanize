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
	create "github.com/viant/mechanize/data/chromeattemptbindingcreate"
	get "github.com/viant/mechanize/data/chromeattemptbindingget"
	"github.com/viant/mechanize/data/loadplan"
	"github.com/viant/mechanize/data/loadrun"
	"github.com/viant/mechanize/model"
	"github.com/viant/xdatly/handler"
)

func TestChromeBindingRequiresConfirmedCommitAndExactReadback(t *testing.T) {
	for _, mode := range []string{"success", "commitUnknown", "commitError", "noCompletion", "readError", "changedReadback", "duplicateReadback", "foreignOwner", "changedDocument", "changedAttempt", "revokedIntent"} {
		t.Run(mode, func(t *testing.T) {
			ptr := func(s string) *string { return &s }
			p, _ := auth.NewPrincipal("fixture", "", "binding-adapter", []string{"desktop:control"})
			p.ClientID = "agent"
			ctx, _ := data.WithScope(auth.WithPrincipal(context.Background(), p), data.Scope{Namespace: p.Namespace, LeaseEpoch: 7})
			attempt := strings.Repeat("a", 64)
			effect := data.ChromeRetirementDigest([]string{"effect", attempt})
			intent := data.CommittedStepIntent{Namespace: p.Namespace, ClientID: p.ClientID, RunID: "run", PlanID: "plan", StepID: "step", AttemptID: attempt, EffectID: effect, LeaseEpoch: 7, RunRevision: 2, SessionID: "session", OperationID: "operation"}
			ctx, revoke, err := data.WithCommittedStepIntent(ctx, p, intent)
			if err != nil {
				t.Fatal(err)
			}
			defer revoke()
			pinned := chrome.ControlAuthority{Owner: p.Namespace, ClientID: p.ClientID, BrokerEpoch: "broker", ChannelEpoch: "channel", ScopeHash: strings.Repeat("b", 64), Lease: chrome.Lease{ID: "lease", Generation: 7}}
			pinned.Document.Identity = chrome.Identity{ProfileChannel: "profile", BrowserInstance: "browser", TabID: 1, DocumentID: "doc", Generation: 1}
			d := chrome.BoundMutation{Action: "element.press", BrowserAttemptID: data.ChromeAttemptBrowserIDV2(p.Namespace, p.ClientID, attempt), Identity: pinned.Document.Identity, BrokerEpoch: pinned.BrokerEpoch, ChannelEpoch: pinned.ChannelEpoch, ScopeHash: pinned.ScopeHash, ControlLease: pinned.Lease, Fingerprint: chrome.MutationFingerprint{Version: 2, SHA256: strings.Repeat("c", 64)}}
			step := model.Step{ID: "step", Action: "element.press"}
			switch mode {
			case "foreignOwner":
				pinned.Owner = "foreign"
			case "changedDocument":
				d.Identity.DocumentID = "foreign"
			case "changedAttempt":
				d.BrowserAttemptID = strings.Repeat("d", 64)
			case "revokedIntent":
				revoke()
			}
			var saved *create.Binding
			var calls []string
			invoke := func(ctx context.Context, _ auth.Principal, req exec.ComponentRequest) (any, error) {
				calls = append(calls, req.Target.Component.Name)
				switch req.Target.Component.Name {
				case "LoadPlan":
					return &loadplan.LoadPlanOutput{Data: []*loadplan.PlanRevision{{ContentHash: ptr(strings.Repeat("d", 64))}}}, nil
				case "LoadRun":
					revision := 1
					return &loadrun.LoadRunOutput{Data: []*loadrun.Run{{Effects: []*loadrun.Effect{{Id: ptr(effect), AttemptId: ptr(attempt), State: ptr("intent"), Revision: &revision, BusinessKey: ptr("business-key")}}}}}, nil
				case "CreateChromeAttemptBinding":
					if _, err := data.RequireChromeAttemptBindingAuthority(ctx); err != nil {
						t.Fatal(err)
					}
					in := req.Input.(*create.CreateChromeAttemptBindingInput)
					saved = in.CreateChromeAttemptBinding[0]
					if saved.Has == nil || !saved.Has.FrameId || !saved.Has.StepIndex {
						t.Fatal("zero-valued required fields missing presence")
					}
					if mode == "commitError" {
						return nil, errors.New("write failure")
					}
					if mode != "noCompletion" {
						state := handler.TransactionCommitted
						if mode == "commitUnknown" {
							state = handler.TransactionCommitUnknown
						}
						req.Completion(handler.Outcome{Transactions: []handler.TransactionOutcome{{State: state}}})
					}
					return &create.CreateChromeAttemptBindingOutput{}, nil
				case "LoadChromeAttemptBinding":
					if mode == "readError" {
						return nil, errors.New("read failure")
					}
					raw, _ := json.Marshal(saved)
					row := &get.Binding{}
					if err := json.Unmarshal(raw, row); err != nil {
						t.Fatal(err)
					}
					if mode == "changedReadback" {
						row.FingerprintDigest = ptr(strings.Repeat("e", 64))
					}
					rows := []*get.Binding{row}
					if mode == "duplicateReadback" {
						rows = append(rows, row)
					}
					return &get.LoadChromeAttemptBindingOutput{Data: rows}, nil
				}
				t.Fatal("unexpected component")
				return nil, nil
			}
			result, err := commitChromeBinding(ctx, p, step, pinned, d, invoke)
			if mode == "success" {
				if err != nil || !result.CommitConfirmed || !result.ReadbackMatched || result.BindingID == "" || len(calls) != 4 {
					t.Fatalf("binding not confirmed: %+v %v %v", result, err, calls)
				}
			} else if err == nil || result.CommitConfirmed || result.ReadbackMatched {
				t.Fatalf("unqualified binding accepted: %+v %v", result, err)
			}
			if (mode == "commitUnknown" || mode == "commitError" || mode == "noCompletion") && len(calls) != 3 {
				t.Fatalf("unconfirmed commit reached readback: %v", calls)
			}
			if (mode == "foreignOwner" || mode == "changedDocument" || mode == "changedAttempt" || mode == "revokedIntent") && len(calls) != 0 {
				t.Fatalf("invalid descriptor reached data: %v", calls)
			}
		})
	}
}
