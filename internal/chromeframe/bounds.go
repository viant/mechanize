// Package chromeframe bounds private enrolled Playwright relay frames. Public
// MCP, ordinary browser commands and replies retain their existing256KiB cap.
package chromeframe

import (
	"bytes"
	"encoding/json"
	"io"
)

const PrivateLimit = 512 * 1024

func OversizeAllowed(raw []byte) bool {
	if len(raw) > PrivateLimit {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, e := d.Token()
	if e != nil || token != json.Delim('{') {
		return false
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, e = d.Token()
		key, ok := token.(string)
		if e != nil || !ok || fields[key] != nil {
			return false
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return false
		}
		fields[key] = value
	}
	token, e = d.Token()
	if e != nil || token != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		return false
	}
	var kind string
	if json.Unmarshal(fields["type"], &kind) != nil {
		return false
	}
	required := []string{}
	allowed := map[string]bool{}
	switch kind {
	case "playwright.send":
		required = []string{"type", "requestId", "relayId", "deadlineUnixMs", "method", "params"}
	case "playwright.result":
		required = []string{"type", "requestId", "relayId"}
		allowed["result"] = true
		allowed["errorCode"] = true
		allowed["dispatchState"] = true
	case "playwright.event":
		required = []string{"type", "relayId", "method", "params"}
	default:
		return false
	}
	for _, key := range required {
		if fields[key] == nil {
			return false
		}
		allowed[key] = true
	}
	for key := range fields {
		if !allowed[key] {
			return false
		}
	}
	for _, key := range []string{"relayId", "requestId"} {
		if raw, exists := fields[key]; exists {
			var value string
			if json.Unmarshal(raw, &value) != nil || len(value) == 0 || len(value) > 128 {
				return false
			}
		}
	}
	if kind == "playwright.result" && (fields["result"] == nil) == (fields["errorCode"] == nil) {
		return false
	}
	return true
}
