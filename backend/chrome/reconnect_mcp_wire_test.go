package chrome_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestProductionWorkerJournalAttentionThroughMCP(t *testing.T) {
	g, p := chrome.ReconnectMCPFixtureForTest(t)
	ctx := auth.WithPrincipal(context.Background(), p)
	runtime, err := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("status dispatched input")
		return automation.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := mcp.New(mcp.Dependencies{Runtime: runtime, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, BrowserStatus: g.BrowserStatus})
	if err != nil {
		t.Fatal(err)
	}
	client := server.AsClient(ctx)
	if _, err = client.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	result, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_browser_status", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	structured, _ := json.Marshal(result.StructuredContent)
	texts := [][]byte{structured}
	for _, content := range result.Content {
		raw, _ := json.Marshal(content)
		var item struct {
			Text string `json:"text"`
		}
		json.Unmarshal(raw, &item)
		if item.Text != "" {
			texts = append(texts, []byte(item.Text))
		}
	}
	if len(texts) != 2 {
		t.Fatal("expected structured and text result")
	}
	for _, raw := range texts {
		var status chrome.BrowserStatus
		if json.Unmarshal(raw, &status) != nil || len(status.Channels) != 1 {
			t.Fatal("invalid MCP status")
		}
		row := status.Channels[0]
		if row.WorkerBuild != 32 || !row.ProcessQualified || !row.ScopeQualified || row.ReconnectPhase != "inventory" || row.ReconnectReason != "journalChanged" || row.ReconnectJournal == nil || *row.ReconnectJournal != (chrome.ReconnectJournalDiagnostic{Reason: "lineageInvalid", Version: 1, HistoryCount: 64, State: "adopted", GrantRelation: "new"}) {
			t.Fatalf("worker diagnostic lost through MCP: %s", raw)
		}
	}
}

func TestProductionWorkerArchiveRolloverAndRestartThroughBroker(t *testing.T) {
	g, p := chrome.RolloverMCPFixtureForTest(t)
	status, err := g.BrowserStatus(auth.WithPrincipal(context.Background(), p), p)
	if err != nil || len(status.Channels) != 1 {
		t.Fatal("worker rollover status unavailable")
	}
	row := status.Channels[0]
	if !row.ExecutorQualified || !row.InventoryComplete || row.AttentionCode != "" || row.ReconnectJournal != nil {
		t.Fatal("lossless archived rollover did not qualify after restart")
	}
}
