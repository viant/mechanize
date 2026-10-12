package chrome

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestPlaywrightPrivateFramingDoesNotWidenOrdinaryCommands(t *testing.T) {
	frame := map[string]any{"type": "playwright.send", "requestId": "r", "relayId": "relay", "deadlineUnixMs": 123, "method": "Runtime.evaluate", "params": map[string]string{"expression": strings.Repeat("x", 343078)}}
	var buffer bytes.Buffer
	if e := WriteFrame(&buffer, frame); e != nil {
		t.Fatal(e)
	}
	raw, e := ReadFrame(&buffer)
	if e != nil || len(raw) <= MaxFrameBytes {
		t.Fatal("private large frame unavailable")
	}
	if e := WriteFrame(io.Discard, map[string]any{"action": "read", "args": strings.Repeat("x", 343078)}); e == nil {
		t.Fatal("ordinary command cap widened")
	}
	var value map[string]any
	json.Unmarshal(raw, &value)
	value["credential"] = "forbidden"
	if e := WriteFrame(io.Discard, value); e == nil {
		t.Fatal("oversize private envelope accepted forbidden field")
	}
}
