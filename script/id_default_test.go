package script

import (
	"bytes"
	"encoding/json"
	"github.com/viant/mechanize/model"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestStableIdentifierDefaultIsExactAndExplicitOptionPreserved(t *testing.T) {
	for _, method := range []string{"getById", "getByTestId"} {
		for _, option := range []string{"", ",exact:true", ",exact:false"} {
			t.Run(method+option, func(t *testing.T) {
				plan, e := Compile(`web.tab(origin:"https://example.test").` + method + `("stable-id"` + option + `).click()`)
				if e != nil {
					t.Fatal(e)
				}
				want := option != ",exact:false"
				if plan.Steps[0].Target.Locator.Exact != want {
					t.Fatal("exact option changed", plan.Steps[0].Target.Locator)
				}
			})
		}
	}
	native, e := Compile(`app("fixture.app").getById("saveAsNameTextField").fill("report.odt")`)
	if e != nil || !native.Steps[0].Target.Locator.Exact {
		t.Fatal("native IDdefault not exact", e)
	}
	for _, method := range []string{"getByRole", "getByName", "getByText", "getByLabel"} {
		plan, e := Compile(`web.tab(origin:"https://example.test").` + method + `("label").click()`)
		if e != nil || plan.Steps[0].Target.Locator.Exact {
			t.Fatal("non-ID default changed", method, e)
		}
	}
}
func TestStableIdentifierDefaultsApplyToNestedSelectorsWithoutChangingTypedIR(t *testing.T) {
	plan, e := Compile(`web.tab(origin:"https://example.test").getById("dialog").getByTestId("save").click()`)
	if e != nil {
		t.Fatal(e)
	}
	target := plan.Steps[0].Target
	if !target.Locator.Exact || target.Ancestor == nil || !target.Ancestor.Locator.Exact {
		t.Fatal("nested stableID not exact")
	}
	// Decode a previously normalized plan whose explicit flag is false. Frontend
	// defaults must not rewrite its immutable persisted semantics.
	plan.Steps[0].Target.Locator.Exact = false
	plan.Steps[0].Target.Ancestor.Locator.Exact = false
	raw, e := json.Marshal(plan)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := DecodeJSON(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	if decoded.Steps[0].Target.Locator.Exact || decoded.Steps[0].Target.Ancestor.Locator.Exact {
		t.Fatal("normalized IR silently migrated")
	}
}
func TestStableIdentifierRegistryPublishesTypedDefaults(t *testing.T) {
	seen := 0
	for _, definition := range (Registry{}).Describe() {
		if definition.Name != "getById" && definition.Name != "getByTestId" {
			continue
		}
		seen++
		if definition.Options["exact"] != model.BoolValue || !reflect.DeepEqual(definition.DefaultOptions["exact"], model.Value{Kind: model.BoolValue, Bool: true}) {
			t.Fatal("stableID defaults absent from discovery", definition)
		}
	}
	if seen != 2 {
		t.Fatal("stableID methods missing")
	}
}

func TestStableIdentifierWorkflowAndGuideExamplesCompile(t *testing.T) {
	plan, e := DecodeYAML(strings.NewReader(envelopeYAML))
	if e != nil {
		t.Fatal(e)
	}
	for _, index := range []int{0, 1} {
		if !plan.Steps[index].Target.Locator.Exact {
			t.Fatal("workflow command IDdefault differsfrom DSL")
		}
	}
	raw, e := os.ReadFile(filepath.Join("..", "examples", "native", "open-calculator-finder.dsl"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Compile(string(raw)); e != nil {
		t.Fatal("native example invalid", e)
	}
	guide, e := os.ReadFile(filepath.Join("..", "docs", "llm-guide.md"))
	if e != nil {
		t.Fatal(e)
	}
	start := strings.Index(string(guide), `let finder = app(`)
	if start < 0 {
		t.Fatal("scoped guide example missing")
	}
	snippet := string(guide)[start:]
	end := strings.Index(snippet, "```")
	if end < 0 {
		t.Fatal("guide code fence missing")
	}
	parsed, e := Compile(snippet[:end])
	if e != nil {
		t.Fatal("guide example invalid", e)
	}
	if !parsed.Steps[1].Target.Locator.Exact {
		t.Fatal("guide stableID selector not exact")
	}
}
