package durable

import (
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/record"
	"strings"
	"testing"
)

func TestRecordedMutationsHaveDurableSourceIdentityWithoutCapturedValues(t *testing.T) {
	surface := model.Surface{Kind: "web", Origin: "https://fixture.test", TabID: "profile/browser/7"}
	secret := "DO_NOT_COPY_CAPTURED_VALUE"
	events := []record.RecordEvent{}
	for i, kind := range []string{"press", "fill", "select", "submit"} {
		event := record.RecordEvent{EventSurface: "web", RecordingID: "recording-fixture", Sequence: uint64(i + 1), Kind: kind, Origin: surface.Origin, Identity: &chrome.Identity{ProfileChannel: "profile", BrowserInstance: "browser", TabID: 7, DocumentID: "document", Generation: 1}, Locator: &chrome.Locator{Strategy: "testId", Value: kind, Exact: true}, Source: "chromeDOM", Trusted: true, SelectorConfidence: "high", Lineage: kind}
		if kind == "fill" || kind == "select" {
			event.Value = &secret
			event.Redacted = true
		}
		events = append(events, event)
	}
	exported, err := (record.Compiler{}).Compile(record.Request{Surface: surface, Reviewed: true}, events, nil)
	if err != nil || len(exported.Plan.Steps) != 4 {
		t.Fatal("recorded steps missing", err)
	}
	keys := map[string]bool{}
	for _, step := range exported.Plan.Steps {
		key, err := effectBusinessKey(exported.Plan, step, map[string]model.Value{})
		if err != nil || key == "" {
			t.Fatal("actual durable admission rejected recording identity", err)
		}
		if keys[key] || strings.Contains(key, secret) {
			t.Fatal("duplicate key or captured value leakage")
		}
		keys[key] = true
		if err = step.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if exported.Report.ProductionReady || exported.Report.BusinessSuccess {
		t.Fatal("source identity promoted business qualification")
	}
	found := false
	for _, issue := range exported.Report.ReviewIssues {
		found = found || issue.Code == "effectReviewRequired"
	}
	if !found {
		t.Fatal("business-effect review omitted")
	}
	events[0].RecordingID = ""
	missing, err := (record.Compiler{}).Compile(record.Request{Surface: surface, Reviewed: true}, events[:1], nil)
	if err != nil || len(missing.Plan.Steps) != 0 || len(missing.DraftActions) != 1 {
		t.Fatal("unidentified event was executed or discarded", err)
	}
}
