package mcp

import (
	"encoding/json"
	"testing"

	"github.com/viant/mcp-protocol/schema"
)

func TestControllerAdvertisedSkillReferenceHasValidResourceMetadata(t *testing.T) {
	d, id, ctx, _ := controllerFixture(t)
	const uri = "skill://mechanize-desktop/references/chrome-actions.md"
	out := controllerCall(t, d, ctx, id, "mechanize_resource_read", map[string]any{"uri": uri})
	if out.IsError != nil && *out.IsError {
		t.Fatal("advertised skill reference rejected")
	}
	body := controllerBody(t, out)
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var resource schema.ReadResourceResult
	if err = json.Unmarshal(encoded, &resource); err != nil {
		t.Fatal("resource fails current protocol decoder", err)
	}
	if resource.CacheScope != schema.ReadResourceResultCacheScopePrivate || resource.ResultType != "complete" || resource.TtlMs != 0 || len(resource.Contents) == 0 {
		t.Fatal("private uncached completed guide required")
	}
}
