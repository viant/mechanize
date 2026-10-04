package darwin

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"testing"
)

func framedBytes(body []byte) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(len(body)))
	buf.Write(body)
	return buf.Bytes()
}

func TestCaptureResponseFrameBoundIsMethodSpecific(t *testing.T) {
	body := bytes.Repeat([]byte("x"), MaximumFrameBytes+1)
	encoded := framedBytes(body)
	for _, method := range []string{"doctor", "capture.image", "windows.clickFrame", "windows.captureFrame.extra", ""} {
		reader := bytes.NewReader(encoded)
		if _, err := readResponseFrame(reader, method); err == nil || reader.Len() != len(body) {
			t.Fatalf("ordinary method %q consumed oversized reply", method)
		}
	}
	actual, err := readResponseFrame(bytes.NewReader(encoded), "windows.captureFrame")
	if err != nil || !bytes.Equal(actual, body) {
		t.Fatal("bounded full frame capture reply rejected", err)
	}
	if _, err = readFrame(bytes.NewReader(encoded)); err == nil {
		t.Fatal("request/default frame limit widened")
	}
	for _, count := range []uint32{0, uint32(MaximumWindowFrameResponseBytes + 1)} {
		var header bytes.Buffer
		binary.Write(&header, binary.BigEndian, count)
		if _, err = readResponseFrame(&header, "windows.captureFrame"); err == nil {
			t.Fatal("capture response bound bypassed")
		}
	}
	truncated := encoded[:len(encoded)-1]
	if _, err = readResponseFrame(bytes.NewReader(truncated), "windows.captureFrame"); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated capture reply: %v", err)
	}
}

func TestClientCaptureResponseLimitRetainsRequestIdentityAndRequestBound(t *testing.T) {
	for _, mode := range []string{"capture", "ordinary", "wrongRequest", "largeRequest", "largeError"} {
		t.Run(mode, func(t *testing.T) {
			client := fixtureClient(t)
			request := Request{ProtocolVersion: ProtocolVersion, RequestID: "capture-response", Method: "windows.captureFrame", DeadlineRemainingMS: 10000}
			switch mode {
			case "ordinary":
				request.Method = "large-ordinary-reply"
			case "wrongRequest":
				request.Params = json.RawMessage(`{"wrongRequest":true}`)
			case "largeRequest":
				request.Params = json.RawMessage(`"` + string(bytes.Repeat([]byte("x"), MaximumFrameBytes)) + `"`)
			case "largeError":
				request.Params = json.RawMessage(`{"errorReply":true}`)
			}
			reply, err := client.Call(context.Background(), request)
			if mode == "capture" {
				if err != nil || len(reply.Result) <= MaximumFrameBytes {
					t.Fatalf("capture full-resolution response failed: %v", err)
				}
			} else if err == nil {
				t.Fatal("request/ordinary/identity limit bypassed")
			}
		})
	}
}
