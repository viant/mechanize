package chromeframe

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPrivateLargeFramesRequireClosedFamilyAndRemainBelowNativeCeiling(t *testing.T) {
	payload := strings.Repeat("x", 343077)
	for _, kind := range []string{"playwright.send", "playwright.result", "playwright.event"} {
		frame := map[string]any{"type": kind, "relayId": "relay"}
		if kind != "playwright.event" {
			frame["requestId"] = "request"
		}
		if kind == "playwright.result" {
			frame["result"] = map[string]any{"value": payload}
		} else {
			frame["method"] = "Runtime.evaluate"
			frame["params"] = map[string]any{"expression": payload}
			if kind == "playwright.send" {
				frame["deadlineUnixMs"] = 123
			}
		}
		raw, _ := json.Marshal(frame)
		if len(raw) <= 256*1024 || len(raw) >= 1024*1024 || !OversizeAllowed(raw) {
			t.Fatal("actual injected script-sized frame refused", kind)
		}
		duplicate := append([]byte(`{"type":"`+kind+`",`), raw[1:]...)
		if OversizeAllowed(duplicate) {
			t.Fatal("duplicate type accepted")
		}
		frame["credential"] = "forbidden"
		raw, _ = json.Marshal(frame)
		if OversizeAllowed(raw) {
			t.Fatal("ordinary credential/extra field allowed")
		}
	}
	for _, kind := range []string{"hello", "documents", "controllerRequest", "playwright.open", "future"} {
		raw, _ := json.Marshal(map[string]any{"type": kind, "value": payload})
		if OversizeAllowed(raw) {
			t.Fatal("ordinary oversized frame allowed")
		}
	}
	raw, _ := json.Marshal(map[string]any{"type": "playwright.result", "requestId": "r", "relayId": "relay", "result": strings.Repeat("x", PrivateLimit)})
	if OversizeAllowed(raw) {
		t.Fatal("above private cap allowed")
	}
}
