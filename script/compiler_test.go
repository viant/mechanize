package script

import (
	"encoding/json"
	"github.com/viant/mechanize/model"
	"reflect"
	"strings"
	"testing"
)

func TestMixedSurfaceTypedBindings(t *testing.T) {
	source := `// mixed scope, no activation
let nativeCase = app("com.example.CaseDesk").window(documentKey: $input.caseID)
let crm = web.tab(origin: "https://crm.example.test", title: "Cases")
let summary = nativeCase.getById("case-summary").read("value")
crm.getByLabel("Summary", exact: true).fill(summary)
expect(crm.getByLabel("Summary", exact: true)).toHaveValue(summary, timeout: 5s)
nativeCase.getByRole("button", name: "Export", exact: true).click()`
	p, err := Compile(source)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Steps) != 4 || p.Steps[0].Action != "element.read" || p.Steps[3].Action != "element.press" {
		t.Fatalf("unexpected steps %+v", p.Steps)
	}
	if p.Steps[1].Arguments["value"].Ref != "binding.summary" {
		t.Fatal("lost typed reference")
	}
	if p.Steps[1].Effect.Class != model.ExternalNonIdempotent {
		t.Fatal("mutation incorrectly downgraded")
	}
	if p.Steps[2].TimeoutMs != 5000 {
		t.Fatal("duration normalization")
	}
	data, _ := json.Marshal(p)
	decoded, err := DecodePlan(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, decoded) {
		t.Fatal("JSON frontend changed IR")
	}
	ast, err := Parse(source)
	if err != nil {
		t.Fatal(err)
	}
	formatted := (Formatter{}).Print(ast)
	again, err := Compile(formatted)
	if err != nil {
		t.Fatalf("%s\n%v", formatted, err)
	}
	for i := range p.Steps {
		p.Steps[i].Source = model.SourceSpan{}
		again.Steps[i].Source = model.SourceSpan{}
	}
	if !reflect.DeepEqual(p, again) {
		t.Fatal("formatter changed normalized IR")
	}
}
func TestLiteralContentAndCompositeValues(t *testing.T) {
	p, err := Compile("let data = {\"literal\": \"${input.x} $foo \\\"quote\\\"\\nline\", \"items\": [true, 5, $input.x]}\napp(\"fixture\").getById(\"a\").fill(\"${unsafe}\")")
	if err != nil {
		t.Fatal(err)
	}
	if p.Steps[0].Arguments["value"].String != "${unsafe}" {
		t.Fatal("literal expanded")
	}
	if p.Bindings[0].Value.Object["items"].Array[2].Ref != "input.x" {
		t.Fatal("composite reference lost")
	}
}
func TestClosedLanguageErrors(t *testing.T) {
	cases := []string{
		`let x = app("fixture"); let x = app("fixture")`,
		`let app = app("fixture")`,
		`app("fixture").getById("x").click(unknown: true)`,
		`app("fixture").getById("x", exact: true, "late").click()`,
		`app("fixture").getById("x", exact: true, exact: false).click()`,
		`app("fixture").getById($total).click()`,
		`app("fixture").getById("x").click().read("value")`,
		`app("fixture").getById(app("fixture").getById("x").click()).click()`,
		`expect(app("fixture")).not.not.toBeVisible()`,
		`app("fixture").getById("x").click(timeout: 61m)`,
		`app("fixture").getById("x").click(timeout: 0ms)`,
		`app("fixture").getById("x").click() junk`,
		`app("fixture").getById("x").eval("code")`,
		`app("fixture").getById("\x61").click()`,
		`let x = {"k": 1, "k": 2}`,
		`let x = [app("fixture").getById("x").click()]`,
		`let x = 9223372036854775808`,
		`web.tab(title: "Ambiguous").getById("x").click()`,
	}
	for _, src := range cases {
		t.Run(src, func(t *testing.T) {
			_, err := Compile(src)
			if err == nil {
				t.Fatalf("accepted %s", src)
			}
			var e *Error
			if !strings.Contains(err.Error(), "step ") {
				e, _ = err.(*Error)
				if e == nil || e.Position.Line < 1 || e.Position.Column < 1 {
					t.Fatalf("missing source diagnostic: %v", err)
				}
			}
		})
	}
}
func TestCapabilityFailureIsExplicit(t *testing.T) {
	p, err := Compile(`app("fixture").getByTestId("x").read("text")`)
	if err != nil {
		t.Fatal(err)
	}
	err = (Registry{}).CheckCapabilities(p, map[string]bool{"native:attributeRead": true})
	if err == nil || !strings.Contains(err.Error(), "native:testIdLocator") {
		t.Fatalf("unsupported capability not rejected: %v", err)
	}
}
func TestStrictStructuredFrontend(t *testing.T) {
	p, _ := Compile(`app("fixture").getById("x").click()`)
	b, _ := json.Marshal(p)
	bad := strings.Replace(string(b), `"action":"element.press"`, `"action":"element.press","eval":"unsafe"`, 1)
	if _, err := DecodePlan(strings.NewReader(bad)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := DecodePlan(strings.NewReader(string(b) + ` {}`)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	p.Steps[0].Effect.Class = model.ReadOnly
	if err := p.Validate(); err == nil {
		t.Fatal("effect downgrade accepted")
	}
	p.Steps[0].Effect.Class = model.ExternalNonIdempotent
	p.Steps[0].Target.Cardinality = "all"
	if err := p.Validate(); err == nil {
		t.Fatal("plural mutation accepted")
	}
}
func FuzzParseNoPanic(f *testing.F) {
	f.Add(`expect(app("fixture")).not.toBeVisible(timeout: 1s)`)
	f.Add(`let values = [1, {"x": false}]`)
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			t.Skip()
		}
		_, _ = Compile(s)
	})
}
