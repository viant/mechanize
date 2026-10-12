package host

import (
	"encoding/json"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	page "github.com/viant/mechanize/data/chromeattemptbindingpage"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"strings"
	"testing"
)

func TestChromeReconnectProjectionPreservesOriginalDispatchWithoutBusinessPromotion(t *testing.T) {
	for _, mode := range []string{"unverified", "unknown", "uncommittedOutcome", "missingOutcome", "foreignClientBinding", "foreignScope", "missingPlan", "changedPlan", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			p, f, _, old := retirementMatchFixture(t, false)
			b := old[0]
			receipt := integration.StepResult{DispatchState: "dispatched", VerificationState: "unknown", Value: &model.Value{Kind: "string", String: "SECRET-CANARY"}}
			if mode == "unknown" {
				receipt.DispatchState = "unknown"
			}
			payload, _ := json.Marshal(receipt)
			b.Outcomes[0].PayloadJson = retirementValue(string(payload))
			b.Effect.EvidenceJson = retirementValue(string(payload))
			b.Effect.State = retirementValue("unknown")
			plan := model.Plan{Steps: []model.Step{{ID: *b.StepId, Action: "element.press"}}}
			b.StepDigest = retirementValue(data.ChromeRetirementDigest(plan.Steps[0]))
			raw, _ := json.Marshal(struct {
				Plan model.Plan `json:"plan"`
			}{plan})
			hash := data.ChromeAttemptRawDigest(string(raw))
			b.PlanContentDigest = retirementValue(hash)
			encoded, _ := json.Marshal(b)
			row := &page.Binding{}
			json.Unmarshal(encoded, row)
			row.Plan = &page.Plan{Namespace: b.Namespace, Id: b.PlanId, ContentHash: retirementValue(hash), ContentJson: retirementValue(string(raw))}
			switch mode {
			case "uncommittedOutcome":
				row.Outcomes = nil
				row.Effect.Revision = retirementValue(1)
				row.Effect.State = retirementValue("intent")
				row.Effect.EvidenceJson = nil
				receipt.DispatchState = "unknown"
			case "missingOutcome":
				row.Outcomes = nil
			case "foreignClientBinding":
				row.ClientId = retirementValue("foreign")
			case "foreignScope":
				row.ScopeHash = retirementValue(strings.Repeat("f", 64))
			case "missingPlan":
				row.Plan = nil
			case "changedPlan":
				row.Plan.ContentJson = retirementValue("{}")
			}
			rows := []*page.Binding{row}
			if mode == "duplicate" {
				rows = append(rows, row)
			}
			scope := chrome.ReconnectBindingScope{ProfileChannel: f.ProfileChannel, BrowserInstance: f.BrowserInstance, ScopeHash: f.ScopeHash}
			out, e := projectChromeReconnectBindings(p, scope, rows)
			if mode == "unverified" || mode == "unknown" || mode == "uncommittedOutcome" {
				if e != nil || len(out) != 1 || out[0].DispatchState != receipt.DispatchState {
					t.Fatal("original dispatch changed", e)
				}
				public, _ := json.Marshal(out)
				if strings.Contains(string(public), "CANARY") {
					t.Fatal("private outcome crossed metadata boundary")
				}
				if *row.Effect.State != "unknown" && mode != "uncommittedOutcome" {
					t.Fatal("business effect changed")
				}
			} else if e == nil || out != nil {
				t.Fatal("incomplete/foreign graph accepted")
			}
		})
	}
}
