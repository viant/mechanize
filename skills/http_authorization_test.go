package skills

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	datlymcp "github.com/viant/datly/mcp"
	native "github.com/viant/datly/mcp/server"
	upstream "github.com/viant/mcp"
	"github.com/viant/mcp-protocol/authorization"
	oauthmeta "github.com/viant/mcp-protocol/oauth2/meta"
	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mcp/client"
)

func TestDatlyEmbeddedSkillsHTTPAuthorization(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			folders, err := Folders()
			if err != nil {
				t.Fatal(err)
			}
			secret := make([]byte, 32)
			if _, err = rand.Read(secret); err != nil {
				t.Fatal(err)
			}
			tokenValue := hex.EncodeToString(secret)
			rule := &authorization.Authorization{RequiredScopes: []string{"skills:read"}, ProtectedResourceMetadata: &oauthmeta.ProtectedResourceMetadata{Resource: "https://fixture.invalid/mechanize-skills"}}
			service, err := datlymcp.New(datlymcp.Config{Folders: folders, Invoker: noSkillInvocation{}, Authorization: &authorization.Policy{Global: rule}})
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			server, err := native.New(native.Config{Service: service, Implementation: schema.Implementation{Name: "mechanize-datly-skills-test", Version: "fixture"}, Transport: native.TransportConfig{Kind: native.TransportStreamable, Address: listener.Addr().String()}, ResourceAuthorizer: func(_ context.Context, token *authorization.Token, policy *authorization.Authorization) error {
				if token == nil || subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(token.Token, "Bearer ")), []byte(tokenValue)) != 1 || len(policy.RequiredScopes) != 1 || policy.RequiredScopes[0] != "skills:read" {
					return fmt.Errorf("unauthorized fixture request")
				}
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			httpServer, err := server.HTTP()
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- httpServer.Serve(listener) }()
			defer func() {
				_ = httpServer.Close()
				stop, finish := context.WithTimeout(context.Background(), 2*time.Second)
				defer finish()
				_ = server.Shutdown(stop)
				select {
				case <-done:
				case <-stop.Done():
					t.Error("endpoint shutdown timeout")
				}
			}()
			endpoint := "http://" + listener.Addr().String() + "/mcp"
			t.Logf("Started Datly skill router: %s", endpoint)
			c, err := upstream.NewClientWithContext(ctx, nil, &upstream.ClientOptions{Name: "mechanize-skills-acceptance", Version: "fixture", ProtocolVersion: version, Transport: upstream.ClientTransport{Type: "streamable", ClientTransportHTTP: upstream.ClientTransportHTTP{URL: endpoint}}})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			for _, token := range []string{"", "invalid-fixture-token"} {
				opt := client.WithAuthToken(token)
				if _, err = c.ListSkills(ctx, nil, opt); err == nil {
					t.Fatal("unauthorized skills listing")
				}
				if _, err = c.GetSkill(ctx, Entrypoint, opt); err == nil {
					t.Fatal("unauthorized skill manifest")
				}
				if _, err = c.ReadResource(ctx, &schema.ReadResourceRequestParams{Uri: Entrypoint}, opt); err == nil {
					t.Fatal("unauthorized skill bytes")
				}
				if _, err = c.ReadResource(ctx, &schema.ReadResourceRequestParams{Uri: "skill://mechanize-desktop/references/connection.md"}, opt); err == nil {
					t.Fatal("unauthorized supporting bytes")
				}
				for _, name := range []string{datlymcp.SkillListTool, datlymcp.SkillGetTool} {
					if result, callErr := c.CallTool(ctx, &schema.CallToolRequestParams{Name: name, Arguments: map[string]any{"uri": Entrypoint}}, opt); callErr == nil && (result.IsError == nil || !*result.IsError) {
						t.Fatalf("unauthorized compatibility tool %s", name)
					}
				}
			}
			allowed := client.WithAuthToken(tokenValue)
			list, err := c.ListSkills(ctx, nil, allowed)
			if err != nil || len(list.Skills) != 6 {
				t.Fatalf("authorized catalog: %v", err)
			}
			for _, entry := range list.Skills {
				manifest, err := c.GetSkill(ctx, entry.Uri, allowed)
				if err != nil {
					t.Fatal(err)
				}
				for _, file := range manifest.Skill.Resources.Files {
					read, err := c.ReadResource(ctx, &schema.ReadResourceRequestParams{Uri: file.Uri}, allowed)
					if err != nil || len(read.Contents) != 1 {
						t.Fatalf("authorized read %s: %v", file.Uri, err)
					}
				}
			}
			for _, name := range []string{datlymcp.SkillListTool, datlymcp.SkillGetTool} {
				args := map[string]any{}
				if name == datlymcp.SkillGetTool {
					args["uri"] = Entrypoint
				}
				result, err := c.CallTool(ctx, &schema.CallToolRequestParams{Name: name, Arguments: args}, allowed)
				if err != nil || result.IsError != nil && *result.IsError {
					t.Fatalf("authorized compatibility %s: %v", name, err)
				}
			}
			if _, err = c.ReadResource(ctx, &schema.ReadResourceRequestParams{Uri: "skill://mechanize-desktop/../work_in_progress/handoff.md"}, allowed); err == nil {
				t.Fatal("authorized caller escaped skill root")
			}
		})
	}
}
