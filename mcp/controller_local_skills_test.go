package mcp

import (
	"context"
	"testing"
	"testing/fstest"

	skillformat "github.com/viant/mcp-protocol/extension/skills"
	"github.com/viant/mechanize/auth"
	bundled "github.com/viant/mechanize/skills"
)

func TestControllerDiscoversAndRetrievesLocalGuide(t *testing.T) {
	const uri = "skill://local-navigation/SKILL.md"
	const text = "---\nname: local-navigation\ndescription: Local application navigation\n---\n\nUse current observed controls.\n"
	compiled, err := (skillformat.Compiler{Source: fstest.MapFS{"SKILL.md": &fstest.MapFile{Data: []byte(text)}}}).Compile(context.Background(), uri)
	if err != nil {
		t.Fatal(err)
	}
	loads := 0
	d, id, ctx, actions := controllerFixture(t, func(deps *Dependencies) {
		deps.LocalSkills = func(ctx context.Context, p auth.Principal) ([]bundled.LocalGuide, error) {
			if p.ClientID != "controller:fixture" {
				t.Fatal("local guide loaded outside controller identity")
			}
			loads++
			return []bundled.LocalGuide{{Compiled: compiled, EntrypointText: text}}, nil
		}
	})
	catalog, err := d.ListTools(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	available := map[string]bool{}
	for _, tool := range catalog.Tools {
		available[tool.Name] = true
	}
	if !available["skill_list"] || !available["skill_get"] {
		t.Fatal("browser controller omits skill tools")
	}
	listed := controllerBody(t, controllerCall(t, d, ctx, id, "skill_list", map[string]any{}))
	found := false
	for _, entry := range listed["skills"].([]any) {
		if entry.(map[string]any)["uri"] == uri {
			found = true
		}
	}
	if !found {
		t.Fatal("local guide missing from browser controller discovery")
	}
	got := controllerBody(t, controllerCall(t, d, ctx, id, "skill_get", map[string]any{"uri": uri}))
	if got["entrypointText"] != text {
		t.Fatal("browser controller changed local guide text")
	}
	if loads != 1 || actions.Load() != 0 {
		t.Fatal("skill discovery must reuse its catalog without running automation")
	}
}
