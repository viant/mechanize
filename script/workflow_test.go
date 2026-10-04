package script

import (
	"bytes"
	"encoding/json"
	"github.com/viant/mechanize/model"
	"reflect"
	"strings"
	"testing"
)

const envelopeYAML = `schemaVersion: 1
name: attach-case-report
goal:
  description: Attach the requested report to the case record.
  successCriteria:
    - The case record shows the report attachment.
    - The attachment belongs to the requested case.
inputs:
  caseID: {type: string, required: true}
requires:
  semanticsProfiles: [fixture.attach.v1]
  adapters: [caseSystem]
surfaces:
  crm: {kind: web, origin: "https://crm.example.test"}
objective:
  kind: adapter
  adapter: caseSystem
  name: reportAttached
  inputs: {caseID: {kind: reference, ref: input.caseID}}
  scope: {surfaceRef: crm}
  timeoutMs: 30000
  freshnessMs: 1000
  requiredAuthority: authoritative
recovery: {maxRepairs: 3, maxElapsedMs: 120000, onUnknownEffect: needsAttention}
checkpoints:
  - {name: before-submit, levels: [evidence, runner]}
steps:
  - id: case-title
    command: 'let title = crm.getById("title").read("text")'
  - id: fill-summary
    command: 'crm.getById("summary").fill(title)'
  - id: attach
    command: 'crm.getByRole("button", name: "Attach").click()'
    purpose: Submit the attachment request for the identified case.
    semanticsProfile: fixture.attach.v1
    effect:
      class: externalNonIdempotent
      businessKey: {caseID: {kind: reference, ref: input.caseID}}
      reconcile:
        kind: adapter
        adapter: caseSystem
        name: attachmentByCase
        inputs: {caseID: {kind: reference, ref: input.caseID}}
        scope: {surfaceRef: crm}
        timeoutMs: 30000
        freshnessMs: 1000
        requiredAuthority: authoritative
`

func TestWorkflowEnvelopeRoundTrip(t *testing.T) {
	p, err := DecodeYAML(strings.NewReader(envelopeYAML))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Steps) != 3 || p.Steps[0].ID != "case-title" || p.Steps[0].Bind != "title" {
		t.Fatal("command lowering changed identity")
	}
	if p.Bindings[1].Value.Ref != "step.case-title.result" {
		t.Fatalf("read reference not renamed: %+v", p.Bindings)
	}
	if p.Steps[1].Arguments["value"].Expected != model.StringValue {
		t.Fatal("runtime reference lost expected type")
	}
	if p.Steps[2].Effect.Reconcile == nil || p.Recovery.MaxRepairs != 3 {
		t.Fatal("durable metadata lost")
	}
	if p.Goal == nil || len(p.Goal.SuccessCriteria) != 2 || p.Steps[2].Purpose == "" {
		t.Fatal("business goal or step purpose lost during normalization")
	}
	if p.Objective == nil {
		t.Fatal("explicit executable objective was lost")
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := DecodeJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, p2) {
		t.Fatal("normalized JSON plan changed during decoding")
	}
	if p2.Goal.Description != p.Goal.Description || p2.Steps[2].Purpose != p.Steps[2].Purpose {
		t.Fatal("goal metadata changed during JSON round trip")
	}
	if _, err := json.Marshal(Schema()); err != nil {
		t.Fatal(err)
	}
}

func TestGoalMetadataValidationBounds(t *testing.T) {
	p, err := Compile(``)
	if err != nil {
		t.Fatal(err)
	}
	p.Goal = &model.WorkflowGoal{Description: "A business objective", SuccessCriteria: []string{"A visible outcome"}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.Objective != nil {
		t.Fatal("goal metadata must not synthesize an executable objective")
	}
	p.Goal.Description = strings.Repeat("x", 4001)
	if err := p.Validate(); err == nil {
		t.Fatal("oversized goal description accepted")
	}
	p.Goal.Description = "valid"
	p.Goal.SuccessCriteria = make([]string, 17)
	for i := range p.Goal.SuccessCriteria {
		p.Goal.SuccessCriteria[i] = "criterion"
	}
	if err := p.Validate(); err == nil {
		t.Fatal("too many success criteria accepted")
	}
}
func TestStrictEnvelopeSecurity(t *testing.T) {
	for _, bad := range []string{
		strings.Replace(envelopeYAML, "maxRepairs: 3", "maxRepairs: 999", 1),
		strings.Replace(envelopeYAML, "needsAttention", "retry", 1),
		strings.Replace(envelopeYAML, "kind: web, origin:", "kind: web, shell: bad, origin:", 1),
		strings.Replace(strings.Replace(envelopeYAML, "caseID: {type: string", "caseID: {type: number", 1), ".fill(title)", ".fill($input.caseID)", 1),
		strings.Replace(envelopeYAML, "ref: input.caseID", "ref: input.missing", 1),
		strings.Replace(envelopeYAML, "surfaceRef: crm", "surfaceRef: unknown", 1),
		strings.Replace(envelopeYAML, "adapters: [caseSystem]", "adapters: []", 1),
		envelopeYAML + "---\n{}\n",
		"schemaVersion: 1\nschemaVersion: 1\nsteps: []\n",
		"schemaVersion: 1\ninputs: &x {}\nsteps: *x\n",
		"schemaVersion: 1\nname: !evil name\nsteps: []\n",
	} {
		if _, err := DecodeYAML(strings.NewReader(bad)); err == nil {
			t.Fatalf("accepted invalid YAML: %s", bad)
		}
	}
	if _, err := DecodeJSON(strings.NewReader(`{"schemaVersion":1,"schemaVersion":1,"steps":[],"bindings":[]}`)); err == nil {
		t.Fatal("duplicate JSON key accepted")
	}
	if _, err := DecodeJSON(strings.NewReader(strings.Repeat(" ", maxEnvelopeBytes+1))); err == nil {
		t.Fatal("oversized JSON accepted")
	}
}
func TestExtendedSharedActionsAndCardinality(t *testing.T) {
	p, err := Compile(`let scope = web.tab(origin: "https://fixture.test")
scope.getById("agree").check()
scope.getById("agree").uncheck()
scope.getById("country").select("US")
scope.getById("search").pressKey("Enter")
let rows = scope.getByRole("row").all(limit: 20, order: "document").read("text")
scope.getByRole("button").nth(1, order: "document").click()
scope.getByRole("button").within(scope.getById("dialog")).click()`)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Steps) != 7 || p.Steps[4].Target.Cardinality != "all" || p.Steps[4].ResultType != model.ArrayValue || p.Steps[6].Target.Ancestor == nil {
		t.Fatal("typed extended actions incorrect")
	}
	for _, source := range []string{
		`app("fixture").getByRole("button").all(limit: 2).click()`,
		`app("fixture").getByRole("button").nth(0).click()`,
		`app("fixture").getByRole("button").nth(0, order: "document").click()`,
		`let n = 12; app("fixture").getById("x").fill(n)`,
		`let checked = app("fixture").getById("x").read("checked"); app("fixture").getById("y").fill(checked)`,
		`app("fixture").getById("x").within(web.tab(origin: "https://other.test").getById("a")).click()`,
	} {
		if _, err := Compile(source); err == nil {
			t.Fatalf("accepted unsafe expression %s", source)
		}
	}
}
func TestLiteralEscapesThroughYAML(t *testing.T) {
	source := `schemaVersion: 1
steps:
  - id: fill
    command: 'app("fixture").getById("value").fill("${input.secret} $oops \\\"quoted\\\"\nline")'
`
	p, err := DecodeYAML(strings.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p.Steps[0].Arguments["value"].String, "${input.secret} $oops") {
		t.Fatal("literal expanded")
	}
}
func TestEmptyPlanRoundTrip(t *testing.T) {
	p, err := Compile("")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(p)
	again, err := DecodePlan(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, again) {
		t.Fatal("empty collections changed")
	}
}
func TestEnvelopeCommandBoundaries(t *testing.T) {
	for _, command := range []string{`app("fixture").getById("x").click(); app("fixture").getById("y").click()`, `let x = app("fixture")`} {
		input := model.Plan{SchemaVersion: 1, Steps: []model.Step{{ID: "s", Command: command}}}
		if _, err := NormalizeEnvelope(&input); err == nil {
			t.Fatalf("multi-dispatch or no-op command accepted: %s", command)
		}
	}
}
