package chrome

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/png"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/viant/mcp-protocol/schema"
)

func controllerPNG(t *testing.T) []byte {
	t.Helper()
	pixels := image.NewNRGBA(image.Rect(0, 0, 320, 320))
	_, _ = rand.New(rand.NewSource(42)).Read(pixels.Pix)
	for i := 3; i < len(pixels.Pix); i += 4 {
		pixels.Pix[i] = 255
	}
	var out bytes.Buffer
	if e := png.Encode(&out, pixels); e != nil {
		t.Fatal(e)
	}
	if out.Len() <= 192*1024 {
		t.Fatal("fixture must exceed old result budget")
	}
	return out.Bytes()
}
func controllerImageAnswer(pixels []byte) *schema.CallToolResult {
	return &schema.CallToolResult{Content: []schema.CallToolResultContentElem{
		map[string]any{"type": "text", "text": "before", "_meta": map[string]any{"secret": "HOST-ONLY-CANARY"}},
		map[string]any{"type": "image", "mimeType": "image/png", "data": base64.StdEncoding.EncodeToString(pixels), "annotations": map[string]any{"audience": []string{"assistant"}, "priority": 0.5}, "_meta": map[string]any{"secret": "HOST-ONLY-CANARY"}},
		map[string]any{"type": "text", "text": "after"}}, StructuredContent: map[string]any{"width": 320, "_meta": map[string]any{"business": "retained"}}}
}
func TestControllerImageProjectionAndBoundedChunkRoundTrip(t *testing.T) {
	pixels := controllerPNG(t)
	answer := controllerImageAnswer(pixels)
	projected, e := controllerCompleteToolResult(answer)
	if e != nil {
		t.Fatal(e)
	}
	body, e := json.Marshal(projected)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(body, []byte("HOST-ONLY-CANARY")) || !bytes.Contains(body, []byte(`"business":"retained"`)) {
		t.Fatal("metadata policy changed")
	}
	request := &controllerRequest{RequestID: "owned", SessionID: "approved", BrokerEpoch: "broker", ChannelEpoch: "channel", ScopeHash: strings.Repeat("a", 64), Deadline: time.Now().Add(time.Second).UnixMilli()}
	digest := controllerResultDigest(body)
	count := (len(body) + controllerChunkBytes - 1) / controllerChunkBytes
	var joined []byte
	for sequence := 0; sequence < count; sequence++ {
		part := controllerChunk(request, body, digest, sequence)
		var framed bytes.Buffer
		if e = WriteFrame(&framed, part); e != nil {
			t.Fatal(e)
		}
		wire, e := ReadFrame(&framed)
		if e != nil || len(wire) > 192*1024 {
			t.Fatal("chunk exceeds ordinary framing", e)
		}
		var recovered controllerResultChunk
		if e = json.Unmarshal(wire, &recovered); e != nil {
			t.Fatal(e)
		}
		if recovered.SessionID != request.SessionID || recovered.RequestID != request.RequestID || recovered.Sequence != sequence || recovered.Count != count || recovered.TotalBytes != len(body) || recovered.DeadlineUnixMS != request.Deadline {
			t.Fatal("original transfer binding changed")
		}
		data, e := base64.StdEncoding.Strict().DecodeString(recovered.Data)
		if e != nil {
			t.Fatal(e)
		}
		joined = append(joined, data...)
	}
	if !bytes.Equal(body, joined) || controllerResultDigest(joined) != digest {
		t.Fatal("result bytes changed")
	}
	var result struct {
		Content []map[string]json.RawMessage `json:"content"`
	}
	if e = json.Unmarshal(joined, &result); e != nil || len(result.Content) != 3 {
		t.Fatal("content ordering lost")
	}
	var encoded string
	json.Unmarshal(result.Content[1]["data"], &encoded)
	imageBytes, _ := base64.StdEncoding.DecodeString(encoded)
	decoded, e := png.Decode(bytes.NewReader(imageBytes))
	if e != nil || decoded.Bounds() != image.Rect(0, 0, 320, 320) || !bytes.Equal(imageBytes, pixels) {
		t.Fatal("real PNG changed", e)
	}
}
func TestControllerImageProjectionRejectsMalformedAndOversizeWithoutFlattening(t *testing.T) {
	for _, block := range []any{map[string]any{"type": "image", "data": "!!!!", "mimeType": "image/png"}, map[string]any{"type": "image", "data": "YQ==", "mimeType": "text/html"}, map[string]any{"type": "image", "data": "YQ==", "mimeType": "image/png", "url": "https://unbound.invalid"}, map[string]any{"type": "text", "text": "public", "annotations": map[string]any{"secret": "not public"}}, map[string]any{"type": "resource_link", "uri": "file:///private"}} {
		if _, e := controllerCompleteToolResult(&schema.CallToolResult{Content: []schema.CallToolResultContentElem{block}}); controllerTransferCode(e) != "resultTransferInvalid" {
			t.Fatal("malformed content accepted", controllerTransferCode(e))
		}
	}
	oversized := strings.Repeat("A", base64.StdEncoding.EncodedLen(controllerImageLimit)+4)
	if _, e := controllerCompleteToolResult(&schema.CallToolResult{Content: []schema.CallToolResultContentElem{map[string]any{"type": "image", "data": oversized, "mimeType": "image/png"}}}); controllerTransferCode(e) != "resultTransferTooLarge" {
		t.Fatal("oversize image accepted")
	}
}
