package host

import (
	"encoding/json"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/loadplan"
	"github.com/viant/mechanize/model"
	"testing"
)

func TestRetirementHistoryRequiresExactStoredPlanAndStep(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "foreign", "content", "digest", "step", "index", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			p, f, m, rows := retirementMatchFixture(t, false)
			b := rows[0]
			plan := model.Plan{Steps: []model.Step{{ID: *b.StepId, Action: "element.press"}}}
			b.StepDigest = retirementValue(data.ChromeRetirementDigest(plan.Steps[0]))
			if mode == "duplicate" {
				plan.Steps = append(plan.Steps, plan.Steps[0])
			}
			raw, _ := json.Marshal(struct {
				Plan model.Plan `json:"plan"`
			}{plan})
			hash := data.ChromeAttemptRawDigest(string(raw))
			b.PlanContentDigest = retirementValue(hash)
			stored := &loadplan.PlanRevision{Namespace: retirementValue(p.Namespace), Id: b.PlanId, ContentHash: retirementValue(hash), ContentJson: retirementValue(string(raw))}
			plans := map[string]*loadplan.PlanRevision{*b.PlanId: stored}
			switch mode {
			case "missing":
				delete(plans, *b.PlanId)
			case "foreign":
				stored.Namespace = retirementValue("other")
			case "content":
				stored.ContentJson = retirementValue("{}")
			case "digest":
				stored.ContentHash = retirementValue("wrong")
			case "step":
				b.StepDigest = retirementValue(data.ChromeRetirementDigest("other"))
			case "index":
				b.StepIndex = retirementValue(100)
			}
			digest, err := MatchChromeRetirementHistory(p, f, m, rows, plans)
			if mode == "valid" {
				if err != nil || len(digest) != 64 {
					t.Fatal("valid linked plan rejected", err)
				}
			} else if err == nil || digest != "" {
				t.Fatal("unlinked plan accepted")
			}
		})
	}
}
