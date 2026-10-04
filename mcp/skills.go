package mcp

import (
	"context"
	"io/fs"

	"github.com/viant/jsonrpc"
	skillformat "github.com/viant/mcp-protocol/extension/skills"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	bundled "github.com/viant/mechanize/skills"
)

type SkillRef struct {
	URI string `json:"uri"`
}
type SkillListing struct {
	Uri         string                 `json:"uri"`
	Frontmatter map[string]interface{} `json:"frontmatter"`
	Resources   schema.SkillResources  `json:"resources"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Ref         string                 `json:"ref"`
}
type SkillCatalog struct {
	Skills []SkillListing `json:"skills"`
}
type SkillGuide struct {
	Skill          schema.Skill `json:"skill"`
	EntrypointText string       `json:"entrypointText"`
}

func registerSkills(base *protocol.DefaultHandler) error {
	entries, err := fs.ReadDir(bundled.Files, ".")
	if err != nil {
		return err
	}
	catalog := map[string]*skillformat.Static{}
	entrypoints := map[string]string{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		source, err := fs.Sub(bundled.Files, entry.Name())
		if err != nil {
			return err
		}
		uri := "skill://" + entry.Name() + "/SKILL.md"
		compiled, err := (skillformat.Compiler{Source: source}).Compile(context.Background(), uri)
		if err != nil {
			return err
		}
		if err = base.RegisterStaticSkill(compiled); err != nil {
			return err
		}
		raw, err := fs.ReadFile(source, "SKILL.md")
		if err != nil {
			return err
		}
		catalog[uri] = compiled
		entrypoints[uri] = string(raw)
	}
	if err := protocol.RegisterTool[*Empty, *SkillCatalog](base.Registry, "skill_list", "Discover bundled desktop, OpenOffice, recording and scenario-selection guidance. Retrieve the relevant skill for your task.", func(ctx context.Context, _ *Empty) (*schema.CallToolResult, *jsonrpc.Error) {
		entries := base.ListRegisteredSkills()
		listing := make([]SkillListing, 0, len(entries))
		for _, entry := range entries {
			name, _ := entry.Frontmatter["name"].(string)
			description, _ := entry.Frontmatter["description"].(string)
			listing = append(listing, SkillListing{Uri: entry.Uri, Frontmatter: entry.Frontmatter, Resources: entry.Resources, Name: name, Description: description, Ref: entry.Uri})
		}
		return result(SkillCatalog{Skills: listing})
	}); err != nil {
		return err
	}
	if err := protocol.RegisterTool[*SkillRef, *SkillGuide](base.Registry, "skill_get", "Retrieve one exact skill URI and its resource inventory; guidance grants no additional permissions.", func(ctx context.Context, input *SkillRef) (*schema.CallToolResult, *jsonrpc.Error) {
		if input == nil {
			return failure(&unknownSkill{})
		}
		compiled, ok := catalog[input.URI]
		if !ok {
			return failure(&unknownSkill{})
		}
		return result(SkillGuide{compiled.Metadata(), entrypoints[input.URI]})
	}); err != nil {
		return err
	}
	return protocol.RegisterTool[*SkillRef, *schema.ReadResourceResult](base.Registry, "mechanize_resource_read", "Read an exact URI from a bundled skill inventory; arbitrary paths and user artifacts are not accepted here.", func(ctx context.Context, input *SkillRef) (*schema.CallToolResult, *jsonrpc.Error) {
		if input == nil {
			return failure(&unknownSkill{})
		}
		for _, compiled := range catalog {
			if compiled.Contains(input.URI) {
				resource, rpc := compiled.ReadResource(ctx, &schema.ReadResourceRequest{Params: schema.ReadResourceRequestParams{Uri: input.URI}})
				if rpc != nil {
					return failure(rpc)
				}
				return result(resource)
			}
		}
		return failure(&unknownSkill{})
	})
}

type unknownSkill struct{}

func (*unknownSkill) Error() string { return "unknown bundled skill URI" }
