package skills

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/viant/datly/mcp/resource"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
)

func TestDatlySkillFoldersPublishExactEmbeddedInventory(t *testing.T) {
	ctx := context.Background()
	folders, err := Folders()
	if err != nil {
		t.Fatal(err)
	}
	plans, err := (resource.Publisher{}).Compile(ctx, folders)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := resource.NewCatalog(plans)
	if err != nil {
		t.Fatal(err)
	}
	handler := resource.NewHandler(catalog, nil)
	registry := protocol.NewRegistry()
	for _, file := range catalog.Resources() {
		registry.RegisterResource(file, handler.Handle)
	}
	if err = catalog.RegisterSkills(registry); err != nil {
		t.Fatal(err)
	}
	entries := registry.ListRegisteredSkills()
	if len(entries) != 6 {
		t.Fatalf("expected six skills, got %d", len(entries))
	}
	for _, entry := range entries {
		for _, file := range entry.Resources.Files {
			read, rpc := handler.Handle(ctx, &schema.ReadResourceRequest{Params: schema.ReadResourceRequestParams{Uri: file.Uri}})
			if rpc != nil || read == nil || len(read.Contents) != 1 {
				t.Fatalf("resource %s: %v", file.Uri, rpc)
			}
			data := []byte(read.Contents[0].Text)
			if read.Contents[0].Blob != "" {
				data, err = base64.StdEncoding.DecodeString(read.Contents[0].Blob)
				if err != nil {
					t.Fatal(err)
				}
			}
			if file.Size != int64(len(data)) || file.Digest != fmt.Sprintf("sha256:%x", sha256.Sum256(data)) {
				t.Fatalf("inventory bytes mismatch: %s", file.Uri)
			}
		}
	}
	for _, uri := range []string{
		"skill://mechanize-desktop/../work_in_progress/handoff.md",
		"skill://mechanize-desktop/%2e%2e/AGENTS.md",
		"skill://mechanize-desktop/unpublished.txt",
	} {
		if _, rpc := handler.Handle(ctx, &schema.ReadResourceRequest{Params: schema.ReadResourceRequestParams{Uri: uri}}); rpc == nil {
			t.Fatalf("unpublished resource accessible: %s", uri)
		}
	}
}
