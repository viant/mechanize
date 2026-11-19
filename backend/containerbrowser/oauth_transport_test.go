package containerbrowser

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/script"
)

func TestOAuthMCPInitializeAndToolsWithoutOwnerHeader(t *testing.T) {
	v, token := oauthFixture(t)
	h, mcp, err := NewHost(workerFixture(t), script.Policy{AllowAllWeb: true}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	h.Verifier = v
	mcp.UseStreamableHTTP(true)
	server := httptest.NewServer(h.HTTP(mcp.HTTP(context.Background(), "127.0.0.1:0").Handler))
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	var session string
	request := func(method string, params any) map[string]any {
		t.Helper()
		payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
		req, _ := http.NewRequest("POST", server.URL+"/mcp", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+token(nil))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", "2025-11-25")
		if session != "" {
			req.Header.Set("Mcp-Session-Id", session)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 200 {
			t.Fatalf("%s HTTP %d: %s", method, response.StatusCode, raw)
		}
		if id := response.Header.Get("Mcp-Session-Id"); id != "" {
			session = id
		}
		var decoded map[string]any
		if strings.Contains(response.Header.Get("Content-Type"), "text/event-stream") {
			scanner := bufio.NewScanner(bytes.NewReader(raw))
			for scanner.Scan() {
				if data, ok := strings.CutPrefix(scanner.Text(), "data:"); ok {
					err = json.Unmarshal([]byte(data), &decoded)
					break
				}
			}
		} else {
			err = json.Unmarshal(raw, &decoded)
		}
		if err != nil || decoded == nil || decoded["error"] != nil {
			t.Fatalf("%s result %s: %v", method, raw, err)
		}
		result, ok := decoded["result"].(map[string]any)
		if !ok {
			t.Fatalf("%s missing result", method)
		}
		return result
	}
	request("initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "oauth-fixture", "version": "1"}})
	if session == "" {
		t.Fatal("transport session not returned")
	}
	listing := request("tools/list", map[string]any{})
	tools, ok := listing["tools"].([]any)
	if !ok || len(tools) == 0 {
		t.Fatal("tools not discovered")
	}
	result := request("tools/call", map[string]any{"name": "mechanize_capabilities", "arguments": map[string]any{}})
	if result["isError"] == true {
		t.Fatalf("capabilities failed: %v", result)
	}
}
