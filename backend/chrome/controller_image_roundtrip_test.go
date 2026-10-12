package chrome

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os/exec"
	"testing"
	"time"

	"github.com/viant/mcp-protocol/schema"
)

type controllerImageDispatchFixture struct{ controllerDispatchFixture }

func (f *controllerImageDispatchFixture) ListTools(context.Context, ControllerIdentity) (*schema.ListToolsResult, error) {
	var tools []schema.Tool
	e := json.Unmarshal([]byte(`[{"name":"mechanize_describe","inputSchema":{"type":"object"}}]`), &tools)
	return &schema.ListToolsResult{Tools: tools}, e
}

func TestControllerImageActualGoExtensionRoundTrip(t *testing.T) {
	pixels := controllerPNG(t)
	controllerImageRoundTrip(t, pixels, controllerImageAnswer(pixels), false)
}

// Test-only seam joins canonical MCP capture projection to the actual native
// chunk sender and shipped extension reassembler without an import cycle.
func ControllerProjectedCaptureRoundTripForTest(t *testing.T, pixels []byte, answer *schema.CallToolResult) {
	controllerImageRoundTrip(t, pixels, answer, true)
}
func controllerImageRoundTrip(t *testing.T, pixels []byte, answer *schema.CallToolResult, capture bool) {
	node, e := exec.LookPath("node")
	if e != nil {
		t.Skip("Node required")
	}
	grant := enrollment(principal(t, "controller-image"), "controller-image-channel")
	b := fixtureBroker(t, grant)
	dispatcher := &controllerImageDispatchFixture{controllerDispatchFixture: controllerDispatchFixture{closed: make(chan struct{}, 1)}}
	if _, err := dispatcher.ListTools(context.Background(), ControllerIdentity{}); err != nil {
		t.Fatal("synthetic catalog decode", err)
	}
	dispatcher.call = func(ctx context.Context, id ControllerIdentity, call ControllerToolCall) (*schema.CallToolResult, error) {
		if id.DocumentID != "controller-document" || call.Name != "mechanize_describe" {
			t.Error("original controller identity lost")
		}
		return answer, ctx.Err()
	}
	b.controllerDispatcher = dispatcher
	conn := connectHost(t, b, grant)
	publish(t, b, conn, grant, document(grant, 7))
	b.mu.Lock()
	c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	c.controllerResultChunkVersion = 1
	c.controllerPolicy = ControllerPolicy{Enabled: true, Origins: []string{"https://shell.fixture.test"}}
	binding := map[string]string{"brokerEpoch": b.epoch, "channelEpoch": c.epoch, "scopeHash": c.scopeHash}
	b.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, node, "../../extension/chrome/test/controller-roundtrip.cjs", "image")
	in, e := child.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	out, e := child.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = child.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		in.Close()
		if child.ProcessState == nil {
			child.Process.Kill()
			child.Wait()
		}
	}()
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 65536), controllerResultLimit+65536)
	encoder := json.NewEncoder(in)
	if e = encoder.Encode(binding); e != nil {
		t.Fatal(e)
	}
	forwardRequest := func() {
		t.Helper()
		if !scanner.Scan() {
			t.Fatal("browser request absent", scanner.Err())
		}
		var envelope struct {
			Type  string
			Value struct{ Error string }
		}
		if json.Unmarshal(scanner.Bytes(), &envelope) != nil || (envelope.Type != "controllerOpen" && envelope.Type != "controllerRequest") {
			t.Fatalf("browser sent terminal instead of request: type=%s error=%s", envelope.Type, envelope.Value.Error)
		}
		if e = WriteFrame(conn, json.RawMessage(scanner.Bytes())); e != nil {
			t.Fatal(e)
		}
	}
	forwardResponse := func() json.RawMessage {
		t.Helper()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		raw, err := ReadFrame(conn)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > 192*1024 {
			t.Fatal("oversize native message")
		}
		if err = encoder.Encode(raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	forwardRequest()
	forwardResponse() // Chrome-owned controller session and approval.
	forwardRequest()
	forwardResponse() // Canonical tool catalog.
	forwardRequest()
	first := forwardResponse()
	var chunk controllerResultChunk
	if json.Unmarshal(first, &chunk) != nil || chunk.Type != "controllerResultChunk" || chunk.Count < 2 {
		t.Fatal("large image was not chunked")
	}
	for sequence := 1; sequence < chunk.Count; sequence++ {
		raw := forwardResponse()
		var next controllerResultChunk
		if json.Unmarshal(raw, &next) != nil || next.Sequence != sequence || next.RequestID != chunk.RequestID || next.SessionID != chunk.SessionID || next.SHA256 != chunk.SHA256 {
			t.Fatal("chunk lost original binding")
		}
	}
	if !scanner.Scan() {
		t.Fatal("terminal browser result absent", scanner.Err())
	}
	var terminal struct {
		Type  string
		Value struct {
			Type, RequestID, Error string
			Result                 struct {
				Content           []map[string]json.RawMessage
				StructuredContent map[string]any
			}
		}
	}
	if json.Unmarshal(scanner.Bytes(), &terminal) != nil || terminal.Type != "fixtureBrowserResult" || terminal.Value.Error != "" || terminal.Value.RequestID != "browser-call" || len(terminal.Value.Result.Content) != len(answer.Content) {
		t.Fatalf("image terminal invalid: type=%s request=%s error=%s contentCount=%d", terminal.Type, terminal.Value.RequestID, terminal.Value.Error, len(terminal.Value.Result.Content))
	}
	if capture {
		var encoded string
		json.Unmarshal(terminal.Value.Result.Content[1]["data"], &encoded)
		decoded, e := base64.StdEncoding.DecodeString(encoded)
		want, _ := json.Marshal(answer.StructuredContent)
		got, _ := json.Marshal(terminal.Value.Result.StructuredContent)
		if e != nil || !bytes.Equal(decoded, pixels) || !bytes.Equal(want, got) || dispatcher.calls.Load() != 1 {
			t.Fatal("canonical capture changed across native chunks/extension")
		}
		if e = child.Wait(); e != nil {
			t.Fatal(e)
		}
		return
	}
	var encoded, mime, before, after string
	json.Unmarshal(terminal.Value.Result.Content[1]["data"], &encoded)
	json.Unmarshal(terminal.Value.Result.Content[1]["mimeType"], &mime)
	json.Unmarshal(terminal.Value.Result.Content[0]["text"], &before)
	json.Unmarshal(terminal.Value.Result.Content[2]["text"], &after)
	decoded, e := base64.StdEncoding.DecodeString(encoded)
	if e != nil || !bytes.Equal(decoded, pixels) || mime != "image/png" || before != "before" || after != "after" || terminal.Value.Result.StructuredContent["width"] != float64(320) || bytes.Contains(scanner.Bytes(), []byte("HOST-ONLY-CANARY")) || dispatcher.calls.Load() != 1 {
		t.Fatal("pixels/order/metadata or exactly-once dispatch changed")
	}
	if e = child.Wait(); e != nil {
		t.Fatal("controller child failed", e)
	}
}
