package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
)

func TestControllerOpenOriginClosedCanonicalResults(t *testing.T) {
	answer := BrowserOpenOriginResult{Outcome: "created", Reason: "none", TabHandle: "profile/browser/7", RunID: "run", OperationID: "operation"}
	calls := 0
	d, id, ctx, _ := controllerFixture(t, func(deps *Dependencies) {
		deps.BrowserOpenOrigin = func(_ context.Context, _ auth.Principal, in BrowserOpenOriginInput) (BrowserOpenOriginResult, error) {
			calls++
			if in.Origin != "https://fixture.test" {
				t.Fatal("invalid origin reached callback")
			}
			return answer, nil
		}
	})
	session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{"name": "opener"}))["sessionId"].(string)
	args := map[string]any{"sessionId": session, "clientRequestId": "open-once", "origin": "https://fixture.test"}
	body := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_browser_open_origin", args))
	if len(body) != 5 || body["outcome"] != "created" || body["tabHandle"] != "profile/browser/7" {
		t.Fatal("canonical result not projected", body)
	}
	for _, invalid := range []BrowserOpenOriginResult{
		{Outcome: "created", Reason: "none", TabHandle: "https://fixture.test/PRIVATE_CANARY", RunID: "run", OperationID: "operation"},
		{Outcome: "unknown", Reason: "PRIVATE_CANARY", RunID: "run", OperationID: "operation"},
		{Outcome: "unknown", Reason: "receiptUnavailable", TabHandle: "profile/browser/7", RunID: "run", OperationID: "operation"},
	} {
		answer = invalid
		out := controllerCall(t, d, ctx, id, "mechanize_browser_open_origin", args)
		raw, _ := json.Marshal(out)
		if out.IsError == nil || !*out.IsError || strings.Contains(string(raw), "PRIVATE_CANARY") {
			t.Fatal("malformed result or private data escaped")
		}
	}
	before := calls
	for _, origin := range []string{"https://fixture.test/path", "https://user:PRIVATE_CANARY@fixture.test", "https://fixture.test/?PRIVATE_CANARY", "javascript:PRIVATE_CANARY"} {
		args["origin"] = origin
		out := controllerCall(t, d, ctx, id, "mechanize_browser_open_origin", args)
		if out.IsError == nil || !*out.IsError {
			t.Fatal("arbitrary URL accepted")
		}
	}
	if calls != before {
		t.Fatal("invalid URL reached opener")
	}
}
