package chrome

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/viant/mcp-protocol/schema"
)

func TestControllerCompleteResultProjectionPreservesErrorsAndWithholdsMeta(t *testing.T) {
	for _, kind := range []string{"", "complete", "input_required", "future"} {
		var answer schema.CallToolResult
		raw := `{"content":[{"type":"text","text":"public result"}],"structuredContent":{"public":true},"isError":true,"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"PRIVATE-CANARY","version":"fixture"}},"resultType":"complete"}`
		if err := json.Unmarshal([]byte(raw), &answer); err != nil {
			t.Fatal(err)
		}
		answer.ResultType = kind
		before, _ := json.Marshal(answer)
		if !strings.Contains(string(before), "PRIVATE-CANARY") {
			t.Fatal("fixture host metadata absent")
		}

		result, err := controllerCompleteToolResult(&answer)
		if kind == "input_required" || kind == "future" {
			if err == nil || result != nil {
				t.Fatal("incomplete result treated as completed")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		wire, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		json.Unmarshal(wire, &fields)
		if len(fields) != 3 || fields["content"] == nil || fields["structuredContent"] == nil || string(fields["isError"]) != "true" || strings.Contains(string(wire), "CANARY") || fields["resultType"] != nil {
			t.Fatal("closed complete/error projection changed")
		}
	}
	if result, err := controllerCompleteToolResult(nil); err == nil || result != nil {
		t.Fatal("missing result became completed")
	}
}
