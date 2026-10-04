package record

import (
	"encoding/json"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/model"
	"strings"
	"testing"
)

func TestCompilePrivacyAndCoverage(t *testing.T) {
	secret := "SEEDED_SECRET_7a"
	surface := model.Surface{Kind: "web", Origin: "https://fixture.invalid", TabID: "fixture/browser/1"}
	events := []chrome.RecordEvent{{RecordingID: "fixture-recording", Sequence: 1, Kind: "start"}, {RecordingID: "fixture-recording", Sequence: 2, Kind: "fill", Trusted: true, Identity: chrome.Identity{ProfileChannel: "fixture", BrowserInstance: "browser", TabID: 1, DocumentID: "doc", Generation: 1}, Origin: surface.Origin, Value: &secret, Redacted: true, Locator: &chrome.Locator{Strategy: "testId", Value: "customer"}, Source: "chromeDOM", SelectorConfidence: "high"}, {RecordingID: "fixture-recording", Sequence: 4, Kind: "press", Trusted: true, Identity: chrome.Identity{ProfileChannel: "fixture", BrowserInstance: "browser", TabID: 1, DocumentID: "doc", Generation: 1}, Origin: surface.Origin, Locator: &chrome.Locator{Strategy: "testId", Value: "submit"}, Source: "chromeDOM", SelectorConfidence: "high"}}
	out, e := (Compiler{}).Compile(Request{Name: "demo", Surface: surface, Reviewed: true}, events, []chrome.RecordGap{{Kind: "gap", UnknownExtent: true}})
	if e != nil {
		t.Fatal(e)
	}
	encoded, _ := json.Marshal(out)
	if strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), "documentId") {
		t.Fatalf("private capture exported: %s", encoded)
	}
	if out.Report.ProductionReady || out.Report.BusinessSuccess || out.Report.Qualification != "unqualified" || len(out.Report.Gaps) != 1 {
		t.Fatal(out.Report)
	}
	if len(out.Plan.Steps) != 2 || out.Plan.Steps[0].Arguments["value"].Kind != model.ReferenceValue {
		t.Fatal(out.Plan)
	}
	found := false
	for _, i := range out.Report.Issues {
		if i.Code == "sequenceGap" {
			found = true
		}
	}
	if !found {
		t.Fatal("gap omitted")
	}
}
func TestCompilerRejectsReorderingAndDefaultText(t *testing.T) {
	c := Compiler{}
	if _, e := c.Normalize([]chrome.RecordEvent{{RecordingID: "fixture-recording", Sequence: 2}, {RecordingID: "fixture-recording", Sequence: 1}}); e == nil {
		t.Fatal("reordered evidence accepted")
	}
	v := model.Value{Kind: model.StringValue, String: "private"}
	if _, e := c.Compile(Request{Surface: model.Surface{Kind: "web", Origin: "https://fixture.invalid", TabID: "a/b/1"}, Inputs: map[string]model.InputDefinition{"secret": {Type: model.StringValue, Default: &v}}}, nil, nil); e == nil {
		t.Fatal("default text accepted")
	}
}
