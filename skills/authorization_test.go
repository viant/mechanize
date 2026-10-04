package skills

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/viant/datly/exec"
	datlymcp "github.com/viant/datly/mcp"
	native "github.com/viant/datly/mcp/server"
	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	"github.com/viant/mechanize/auth"
)

type noSkillInvocation struct{}

func (noSkillInvocation) InvokeComponent(context.Context, exec.ComponentRequest) (any, error) {
	return nil, fmt.Errorf("skill retrieval must not invoke a data component")
}

func TestDatlyEmbeddedSkillsAuthorization(t *testing.T) {
	folders, err := Folders()
	if err != nil {
		t.Fatal(err)
	}
	guard := func(ctx context.Context, uri, action string) error {
		p, err := auth.FromContext(ctx)
		if err != nil || p.Subject != "authorized-reader" {
			return fmt.Errorf("denied")
		}
		if !strings.HasPrefix(uri, "skill://mechanize-") {
			return fmt.Errorf("outside skill namespace")
		}
		return nil
	}
	service, err := datlymcp.New(datlymcp.Config{Folders: folders, Invoker: noSkillInvocation{}, AuthorizeCatalogResource: guard, AuthorizeResource: func(ctx context.Context, uri string) error { return guard(ctx, uri, "retrieve") }})
	if err != nil {
		t.Fatal(err)
	}
	factory, err := native.NewHandler(service)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := factory(context.Background(), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	skills := handler.(protocol.Skills)
	reader, err := auth.NewPrincipal("fixture:issuer", "", "authorized-reader", []string{"skills:read"})
	if err != nil {
		t.Fatal(err)
	}
	denied, err := auth.NewPrincipal("fixture:issuer", "", "other-reader", []string{"skills:read"})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		ctx     context.Context
		allowed bool
	}{
		{"anonymous", context.Background(), false},
		{"other-principal", auth.WithPrincipal(context.Background(), denied), false},
		{"authorized", auth.WithPrincipal(context.Background(), reader), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			listed, rpc := skills.ListSkills(test.ctx, nil)
			want := 0
			if test.allowed {
				want = 6
			}
			if rpc != nil || len(listed.Skills) != want {
				t.Fatalf("catalog: %+v %v", listed, rpc)
			}
			resources, rpc := handler.ListResources(test.ctx, nil)
			if rpc != nil || (len(resources.Resources) > 0) != test.allowed {
				t.Fatalf("resources: %+v %v", resources, rpc)
			}
			for _, folder := range folders {
				uri := folder.URIPrefix + "SKILL.md"
				manifest, rpc := skills.GetSkill(test.ctx, &jsonrpc.TypedRequest[*schema.GetSkillRequest]{Request: &schema.GetSkillRequest{Params: schema.GetSkillRequestParams{Uri: uri}}})
				if (rpc == nil) != test.allowed {
					t.Fatalf("manifest %s: %v", uri, rpc)
				}
				paths := []string{uri}
				if test.allowed {
					for _, file := range manifest.Skill.Resources.Files {
						paths = append(paths, file.Uri)
					}
				} else {
					paths = append(paths, "skill://mechanize-desktop/references/connection.md")
				}
				for _, path := range paths {
					_, rpc = handler.ReadResource(test.ctx, &jsonrpc.TypedRequest[*schema.ReadResourceRequest]{Request: &schema.ReadResourceRequest{Params: schema.ReadResourceRequestParams{Uri: path}}})
					if (rpc == nil) != test.allowed {
						t.Fatalf("read %s: %v", path, rpc)
					}
				}
				get, _ := service.Registry().ToolRegistry.Get(datlymcp.SkillGetTool)
				_, rpc = get.Handler(test.ctx, &schema.CallToolRequest{Params: schema.CallToolRequestParams{Name: datlymcp.SkillGetTool, Arguments: map[string]interface{}{"uri": uri}}})
				if (rpc == nil) != test.allowed {
					t.Fatalf("compatibility get %s: %v", uri, rpc)
				}
			}
			list, _ := service.Registry().ToolRegistry.Get(datlymcp.SkillListTool)
			result, rpc := list.Handler(test.ctx, &schema.CallToolRequest{Params: schema.CallToolRequestParams{Name: datlymcp.SkillListTool}})
			if rpc != nil {
				t.Fatal(rpc)
			}
			entries := result.StructuredContent.(map[string]interface{})["skills"].([]interface{})
			if len(entries) != want {
				t.Fatalf("compatibility catalog: got %d, want %d", len(entries), want)
			}
		})
	}
}
