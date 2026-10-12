package mcp

import (
	"context"
	"io/fs"
	"sync"

	"github.com/viant/jsonrpc"
	skillformat "github.com/viant/mcp-protocol/extension/skills"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	"github.com/viant/mechanize/auth"
	bundled "github.com/viant/mechanize/skills"
)

type LocalSkillSource func(context.Context, auth.Principal) ([]bundled.LocalGuide, error)
type skillCatalogState struct {
	mu          sync.Mutex
	base        *protocol.DefaultHandler
	local       LocalSkillSource
	owner       string
	loaded      bool
	catalog     map[string]*skillformat.Static
	entrypoints map[string]string
}

func (c *skillCatalogState) ensure(ctx context.Context) error {
	if c.local == nil {
		return nil
	}
	p, err := auth.FromContext(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loaded {
		if c.owner != p.Namespace {
			return auth.ErrUnauthorized
		}
		return nil
	}
	guides, err := c.local(ctx, p)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, guide := range guides {
		if guide.Compiled == nil {
			return bundled.ErrLocalSkills
		}
		uri := guide.Compiled.Metadata().Uri
		if c.catalog[uri] != nil || seen[uri] {
			return bundled.ErrLocalSkills
		}
		seen[uri] = true
	}
	for _, guide := range guides {
		if err = c.base.RegisterStaticSkill(guide.Compiled); err != nil {
			return bundled.ErrLocalSkills
		}
		uri := guide.Compiled.Metadata().Uri
		c.catalog[uri] = guide.Compiled
		c.entrypoints[uri] = guide.EntrypointText
	}
	c.owner = p.Namespace
	c.loaded = true
	return nil
}

type localSkillsHandler struct {
	*protocol.DefaultHandler
	catalog *skillCatalogState
}

func (h *localSkillsHandler) ListSkills(ctx context.Context, r *jsonrpc.TypedRequest[*schema.ListSkillsRequest]) (*schema.ListSkillsResult, *jsonrpc.Error) {
	if err := h.catalog.ensure(ctx); err != nil {
		return nil, jsonrpc.NewInvalidParamsError("local skills unavailable", nil)
	}
	return h.DefaultHandler.ListSkills(ctx, r)
}
func (h *localSkillsHandler) GetSkill(ctx context.Context, r *jsonrpc.TypedRequest[*schema.GetSkillRequest]) (*schema.GetSkillResult, *jsonrpc.Error) {
	if err := h.catalog.ensure(ctx); err != nil {
		return nil, jsonrpc.NewInvalidParamsError("local skills unavailable", nil)
	}
	return h.DefaultHandler.GetSkill(ctx, r)
}
func (h *localSkillsHandler) ListResources(ctx context.Context, r *jsonrpc.TypedRequest[*schema.ListResourcesRequest]) (*schema.ListResourcesResult, *jsonrpc.Error) {
	if err := h.catalog.ensure(ctx); err != nil {
		return nil, jsonrpc.NewInvalidParamsError("local skills unavailable", nil)
	}
	return h.DefaultHandler.ListResources(ctx, r)
}
func (h *localSkillsHandler) ReadResource(ctx context.Context, r *jsonrpc.TypedRequest[*schema.ReadResourceRequest]) (*schema.ReadResourceResult, *jsonrpc.Error) {
	if err := h.catalog.ensure(ctx); err != nil {
		return nil, jsonrpc.NewInvalidParamsError("local skills unavailable", nil)
	}
	return h.DefaultHandler.ReadResource(ctx, r)
}

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

func registerSkills(base *protocol.DefaultHandler, local LocalSkillSource) (*skillCatalogState, error) {
	entries, err := fs.ReadDir(bundled.Files, ".")
	if err != nil {
		return nil, err
	}
	catalog := map[string]*skillformat.Static{}
	entrypoints := map[string]string{}
	state := &skillCatalogState{base: base, local: local, catalog: catalog, entrypoints: entrypoints}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		source, err := fs.Sub(bundled.Files, entry.Name())
		if err != nil {
			return nil, err
		}
		uri := "skill://" + entry.Name() + "/SKILL.md"
		compiled, err := (skillformat.Compiler{Source: source}).Compile(context.Background(), uri)
		if err != nil {
			return nil, err
		}
		if err = base.RegisterStaticSkill(compiled); err != nil {
			return nil, err
		}
		raw, err := fs.ReadFile(source, "SKILL.md")
		if err != nil {
			return nil, err
		}
		catalog[uri] = compiled
		entrypoints[uri] = string(raw)
	}
	if err := protocol.RegisterTool[*Empty, *SkillCatalog](base.Registry, "skill_list", "Discover bundled and locally installed application and website guidance. Retrieve the relevant skill for your task.", func(ctx context.Context, _ *Empty) (*schema.CallToolResult, *jsonrpc.Error) {
		if err := state.ensure(ctx); err != nil {
			return failure(err)
		}
		entries := base.ListRegisteredSkills()
		listing := make([]SkillListing, 0, len(entries))
		for _, entry := range entries {
			name, _ := entry.Frontmatter["name"].(string)
			description, _ := entry.Frontmatter["description"].(string)
			listing = append(listing, SkillListing{Uri: entry.Uri, Frontmatter: entry.Frontmatter, Resources: entry.Resources, Name: name, Description: description, Ref: entry.Uri})
		}
		return result(SkillCatalog{Skills: listing})
	}); err != nil {
		return nil, err
	}
	if err := protocol.RegisterTool[*SkillRef, *SkillGuide](base.Registry, "skill_get", "Retrieve one exact skill URI and its resource inventory; guidance grants no additional permissions.", func(ctx context.Context, input *SkillRef) (*schema.CallToolResult, *jsonrpc.Error) {
		if err := state.ensure(ctx); err != nil {
			return failure(err)
		}
		if input == nil {
			return failure(&unknownSkill{})
		}
		compiled, ok := catalog[input.URI]
		if !ok {
			return failure(&unknownSkill{})
		}
		return result(SkillGuide{compiled.Metadata(), entrypoints[input.URI]})
	}); err != nil {
		return nil, err
	}
	err = protocol.RegisterTool[*SkillRef, *schema.ReadResourceResult](base.Registry, "mechanize_resource_read", "Read an exact URI from the registered skill inventory; arbitrary paths and user artifacts are not accepted here.", func(ctx context.Context, input *SkillRef) (*schema.CallToolResult, *jsonrpc.Error) {
		if err := state.ensure(ctx); err != nil {
			return failure(err)
		}
		if input == nil {
			return failure(&unknownSkill{})
		}
		for _, compiled := range catalog {
			if compiled.Contains(input.URI) {
				resource, rpc := compiled.ReadResource(ctx, &schema.ReadResourceRequest{Params: schema.ReadResourceRequestParams{Uri: input.URI}})
				if rpc != nil {
					return failure(rpc)
				}
				// Compiled skill readers may predate resource cache metadata. This
				// exact inventory-owned result is complete, private and uncached;
				// emit valid metadata before the controller's protocol decoder.
				complete := *resource
				if complete.CacheScope == "" {
					complete.CacheScope = schema.ReadResourceResultCacheScopePrivate
				}
				if complete.ResultType == "" {
					complete.ResultType = "complete"
				}
				return result(&complete)
			}
		}
		return failure(&unknownSkill{})
	})
	return state, err
}

type unknownSkill struct{}

func (*unknownSkill) Error() string { return "unknown skill URI" }
