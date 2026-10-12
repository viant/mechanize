package mcp

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/viant/jsonrpc"
	skillformat "github.com/viant/mcp-protocol/extension/skills"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	"github.com/viant/mechanize/auth"
	bundled "github.com/viant/mechanize/skills"
)

func TestLocalSkillsStandardMethodsAndIdentity(t *testing.T) {
	ctx := context.Background()
	p, _ := auth.NewPrincipal("fixture", "", "alice", nil)
	ctx = auth.WithPrincipal(ctx, p)
	uri := "skill://local-fixture/SKILL.md"
	text := "---\nname: local-fixture\ndescription: Local navigation guide\n---\n\nUse observed controls.\n"
	compiled, err := (skillformat.Compiler{Source: fstest.MapFS{"SKILL.md": &fstest.MapFile{Data: []byte(text)}}}).Compile(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	base := protocol.NewDefaultHandler(nil, nil, nil)
	catalog, err := registerSkills(base, func(context.Context, auth.Principal) ([]bundled.LocalGuide, error) {
		calls++
		return []bundled.LocalGuide{{Compiled: compiled, EntrypointText: text}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	h := &localSkillsHandler{DefaultHandler: base, catalog: catalog}
	listed, rpc := h.ListSkills(ctx, nil)
	folders, err := bundled.Folders()
	if err != nil {
		t.Fatal(err)
	}
	if rpc != nil || len(listed.Skills) != len(folders)+1 {
		t.Fatalf("list: %+v %v", listed, rpc)
	}
	got, rpc := h.GetSkill(ctx, &jsonrpc.TypedRequest[*schema.GetSkillRequest]{Request: &schema.GetSkillRequest{Params: schema.GetSkillRequestParams{Uri: uri}}})
	if rpc != nil || got.Skill.Uri != uri {
		t.Fatalf("get: %+v %v", got, rpc)
	}
	if calls != 1 || catalog.entrypoints[uri] != text {
		t.Fatal("catalog not shared/sealed")
	}
	other, _ := auth.NewPrincipal("fixture", "", "bob", nil)
	foreign := auth.WithPrincipal(context.Background(), other)
	if _, rpc := h.ListSkills(foreign, nil); rpc == nil {
		t.Fatal("foreign skills access")
	}
	if _, rpc := h.ListResources(foreign, nil); rpc == nil {
		t.Fatal("foreign resource inventory")
	}
	if err := catalog.ensure(context.Background()); err == nil {
		t.Fatal("anonymous local access")
	}
}
