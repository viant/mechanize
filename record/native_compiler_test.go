package record

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/model"
)

func nativeRecorded(sequence uint64, bundle, kind string) RecordEvent {
	return RecordEvent{EventSurface: "native", RecordingID: "mixed", Sequence: sequence, Kind: kind, NativeIdentity: &NativeIdentity{UID: 501, BundleID: bundle, PID: int32(100 + sequence), StartToken: "process-start", WindowID: "123"}, NativeTarget: &NativeTarget{Role: "AXButton", Identifier: "save", IdentifierQualified: true, NameWithheld: true}, Locator: &chrome.Locator{Strategy: "id", Value: "save", Exact: true}, Source: "nativeAX", Lineage: bundle + ":event", SelectorConfidence: "candidate", Redacted: true}
}
func webRecorded(sequence uint64) RecordEvent {
	return RecordEvent{EventSurface: "web", RecordingID: "mixed", Sequence: sequence, Kind: "press", Identity: &chrome.Identity{ProfileChannel: "profile", BrowserInstance: "browser", TabID: 4, DocumentID: "private-doc", Generation: 2}, Origin: "https://example.test", Locator: &chrome.Locator{Strategy: "testId", Value: "submit", Exact: true}, Source: "chromeDOM", Trusted: true, Lineage: "web-lineage"}
}
func TestMixedNativeAndWebRecordingPreservesReviewLineageWithoutPortableGuessing(t *testing.T) {
	events := []RecordEvent{nativeRecorded(1, "com.apple.Calculator", "press"), nativeRecorded(2, "com.apple.finder", "app.activate"), webRecorded(4)}
	out, err := (Compiler{}).Compile(Request{Name: "mixed", Surface: model.Surface{Kind: "desktop"}, Reviewed: true}, events, []RecordGap{{Kind: "gap", FromSequence: 3, ToSequence: 3, Lost: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Plan.Steps) != 1 || out.Plan.Steps[0].Target.Surface.Kind != "web" || out.Report.ProductionReady || out.Report.BusinessSuccess {
		t.Fatalf("native evidence guessed runnable: %+v", out)
	}
	if len(out.Plan.Surfaces) != 3 || len(out.Report.Provenance) != 3 || out.Report.Provenance[0].NativeIdentity.BundleID != "com.apple.Calculator" || out.Report.Provenance[1].NativeIdentity.BundleID != "com.apple.finder" {
		t.Fatalf("mixedlineage dropped %+v", out.Report.Provenance)
	}
	codes := map[string]bool{}
	for _, problem := range out.Report.ReviewIssues {
		codes[problem.Code] = true
	}
	for _, code := range []string{"sourceNotAttested", "nativeProvenanceReviewRequired", "appActivationSemanticsUnqualified", "sequenceGap"} {
		if !codes[code] {
			t.Fatalf("reviewissue %s missing", code)
		}
	}
	for _, step := range out.Plan.Steps {
		if step.Action == "app.open" {
			t.Fatal("activation reinterpreted as launch")
		}
	}
}
func TestNativePortableLocatorNeedsRoleQualifiedIDAndAttestedReviewedSource(t *testing.T) {
	for _, kind := range []string{"missingrole", "missingid", "digest", "unqualifiedid"} {
		event := nativeRecorded(1, "com.fixture.app", "press")
		event.Trusted = true
		event.SourceAttested = true
		switch kind {
		case "missingrole":
			event.NativeTarget.Role = ""
		case "missingid":
			event.NativeTarget.Identifier = ""
		case "digest":
			event.NativeTarget.IdentifierDigest = strings.Repeat("a", 64)
			event.Locator.Strategy = "idDigest"
		case "unqualifiedid":
			event.NativeTarget.IdentifierQualified = false
		}
		out, err := (Compiler{}).Compile(Request{Surface: model.Surface{Kind: "desktop"}, Reviewed: true}, []RecordEvent{event}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Plan.Steps) != 0 {
			t.Fatalf("guessed %s locator", kind)
		}
	}
	event := nativeRecorded(1, "com.fixture.app", "fill")
	event.Trusted = true
	event.SourceAttested = true
	raw := "CAPTURED_SECRET"
	event.Value = &raw
	checkpoint := &model.CheckpointPolicy{Name: "after-edit", Levels: []string{"evidence"}}
	out, err := (Compiler{}).Compile(Request{Surface: model.Surface{Kind: "desktop"}, Reviewed: true, Checkpoints: map[uint64]*model.CheckpointPolicy{1: checkpoint}}, []RecordEvent{event}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Plan.Steps) != 1 || out.Plan.Steps[0].Checkpoint.Name != "after-edit" || out.Plan.Steps[0].Arguments["value"].Kind != model.ReferenceValue || out.Plan.Inputs["recorded_1"].Default != nil {
		t.Fatalf("canonicalparameter/checkpoint lost %+v", out.Plan)
	}
	payload, _ := json.Marshal(out)
	if strings.Contains(string(payload), raw) {
		t.Fatal("captured text exported")
	}
}
func TestNativeBatchDecoderRejectsTrailingJSONRawTextAndSurfaceSpoof(t *testing.T) {
	payload := `{"recordingId":"native","state":"recording","events":[{"recordingId":"native","sequence":1,"kind":"start","source":"nativeAX","trusted":true}],"gaps":[],"lastSequence":1,"truncated":false}`
	batch, err := DecodeNativeBatch([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if batch.Events[0].EventSurface != "native" || batch.Events[0].Trusted || batch.Events[0].SourceAttested {
		t.Fatal("native source self-attested")
	}
	for _, unsafe := range []string{payload + ` {}`, strings.Replace(payload, `"trusted":true`, `"value":"secret"`, 1), strings.Replace(payload, `"trusted":true`, `"eventSurface":"web"`, 1), strings.Replace(payload, `"trusted":true`, `"clipboard":"secret"`, 1)} {
		if _, err := DecodeNativeBatch([]byte(unsafe)); err == nil {
			t.Fatalf("unsafe native envelope %s", unsafe)
		}
	}
}

func TestUnattestedNativeEventsRetainEditableDraftActionsAndParameterIntent(t *testing.T) {
	fill := nativeRecorded(1, "com.apple.finder", "fill")
	raw := "NEVER_EXPORT_CAPTURED_TEXT"
	fill.Value = &raw
	press := nativeRecorded(2, "com.apple.Calculator", "press")
	activation := nativeRecorded(3, "com.apple.mail", "app.activate")
	checkpoint := &model.CheckpointPolicy{Name: "review-boundary", Levels: []string{"evidence"}}
	out, err := (Compiler{}).Compile(Request{Surface: model.Surface{Kind: "desktop"}, Reviewed: true, Checkpoints: map[uint64]*model.CheckpointPolicy{1: checkpoint}}, []RecordEvent{fill, press, activation}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Plan.Steps) != 0 || len(out.DraftActions) != 3 {
		t.Fatalf("unattestedevidence disappearedor became executable %+v", out)
	}
	draft := out.DraftActions[0]
	if draft.CapturedKind != "fill" || draft.ProposedAction != "element.fill" || !draft.ParameterRequired || draft.InputRef == nil || draft.InputRef.Ref != "input.recorded_1" || draft.Checkpoint.Name != "review-boundary" || draft.NativeIdentity.BundleID != "com.apple.finder" || len(draft.ReviewIssues) == 0 {
		t.Fatalf("editablefilldraft lostintent %+v", draft)
	}
	if out.DraftActions[1].ProposedAction != "element.press" || out.DraftActions[2].CapturedKind != "app.activate" || out.DraftActions[2].ProposedAction != "" {
		t.Fatal("capturedactiontype droppedor activation guessed")
	}
	if out.Plan.Inputs["recorded_1"].Default != nil {
		t.Fatal("capturedfill became parameterdefault")
	}
	payload, _ := json.Marshal(out)
	if strings.Contains(string(payload), raw) {
		t.Fatal("draft retained rawcapturedtext")
	}
}

func TestNativeActivationPreservesActionAndRequiresAllQualificationGates(t *testing.T) {
	for _, mode := range []string{"qualified", "untrusted", "unattested", "unreviewed", "missingRecording"} {
		t.Run(mode, func(t *testing.T) {
			event := nativeRecorded(1, "com.fixture.app", "app.activate")
			event.NativeTarget = nil
			event.Locator = nil
			if mode == "missingRecording" {
				event.RecordingID = ""
			}
			event.Trusted = mode != "untrusted"
			event.SourceAttested = mode != "unattested"
			out, err := (Compiler{}).Compile(Request{Surface: model.Surface{Kind: "desktop"}, Reviewed: mode != "unreviewed"}, []RecordEvent{event}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "qualified" {
				if len(out.Plan.Steps) != 1 || out.Plan.Steps[0].Action != "app.activate" || out.Plan.Steps[0].Target.Locator != nil || out.Plan.Steps[0].Target.Surface.BundleID != "com.fixture.app" {
					t.Fatal("activation changed meaning", out.Plan.Steps)
				}
				if out.Plan.Steps[0].Effect.BusinessKey["recording"].String != "mixed" || out.Plan.Steps[0].Effect.BusinessKey["sequence"].Number != 1 {
					t.Fatal("durable recording identity missing")
				}
				if err = out.Plan.Steps[0].Validate(); err != nil {
					t.Fatal(err)
				}
			} else if len(out.Plan.Steps) != 0 {
				t.Fatal("unqualified activation became executable")
			}
			for _, step := range out.Plan.Steps {
				if step.Action == "app.open" {
					t.Fatal("activation reinterpreted as launch")
				}
			}
			if out.Report.ProductionReady || out.Report.BusinessSuccess {
				t.Fatal("compiler claimed production or business qualification")
			}
		})
	}
}

func TestQualifiedNativeAppLaunchGetsRecordingBusinessIdentity(t *testing.T) {
	event := nativeRecorded(2, "com.fixture.app", "app.open")
	event.Trusted = true
	event.SourceAttested = true
	event.NativeTarget = nil
	event.Locator = nil
	out, err := (Compiler{}).Compile(Request{Surface: model.Surface{Kind: "desktop"}, Reviewed: true}, []RecordEvent{event}, nil)
	if err != nil || len(out.Plan.Steps) != 1 {
		t.Fatal("qualified launch not retained", err)
	}
	step := out.Plan.Steps[0]
	if step.Action != "app.open" || step.Effect.BusinessKey["recording"].String != "mixed" || step.Effect.BusinessKey["sequence"].Number != 2 {
		t.Fatal("launch identity changed")
	}
	if err = step.Validate(); err != nil {
		t.Fatal(err)
	}
}
