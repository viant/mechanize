package chrome

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/viant/mcp-protocol/schema"
)

const controllerResultLimit = 12 * 1024 * 1024
const controllerImageLimit = 8 * 1024 * 1024
const controllerChunkBytes = 96 * 1024
const controllerSmallResultLimit = 192 * 1024

type controllerTransferFailure string

func (e controllerTransferFailure) Error() string { return string(e) }
func controllerTransferCode(e error) string {
	var failure controllerTransferFailure
	if errors.As(e, &failure) {
		return string(failure)
	}
	return "unavailable"
}

type controllerResultProjection struct {
	Content           []map[string]json.RawMessage `json:"content"`
	StructuredContent any                          `json:"structuredContent,omitempty"`
	IsError           *bool                        `json:"isError,omitempty"`
}

func projectControllerContent(content []schema.CallToolResultContentElem) ([]map[string]json.RawMessage, error) {
	if len(content) > 32 {
		return nil, controllerTransferFailure("resultTransferTooLarge")
	}
	out := make([]map[string]json.RawMessage, 0, len(content))
	imageBytes := 0
	for _, item := range content {
		raw, e := json.Marshal(item)
		if e != nil {
			return nil, controllerTransferFailure("resultTransferInvalid")
		}
		if len(raw) > controllerResultLimit {
			return nil, controllerTransferFailure("resultTransferTooLarge")
		}
		var block map[string]json.RawMessage
		if json.Unmarshal(raw, &block) != nil || block == nil {
			return nil, controllerTransferFailure("resultTransferInvalid")
		}
		delete(block, "_meta")
		var kind string
		if json.Unmarshal(block["type"], &kind) != nil {
			return nil, controllerTransferFailure("resultTransferInvalid")
		}
		allowed := map[string]bool{"type": true, "annotations": true}
		switch kind {
		case "text":
			allowed["text"] = true
			var text string
			if json.Unmarshal(block["text"], &text) != nil {
				return nil, controllerTransferFailure("resultTransferInvalid")
			}
		case "image":
			allowed["data"], allowed["mimeType"] = true, true
			var data, mime string
			if json.Unmarshal(block["data"], &data) != nil || json.Unmarshal(block["mimeType"], &mime) != nil {
				return nil, controllerTransferFailure("resultTransferInvalid")
			}
			if mime != "image/png" && mime != "image/jpeg" && mime != "image/webp" && mime != "image/gif" {
				return nil, controllerTransferFailure("resultTransferInvalid")
			}
			if len(data) > base64.StdEncoding.EncodedLen(controllerImageLimit) {
				return nil, controllerTransferFailure("resultTransferTooLarge")
			}
			decoded, e := base64.StdEncoding.Strict().DecodeString(data)
			if e != nil || len(decoded) == 0 || base64.StdEncoding.EncodeToString(decoded) != data {
				return nil, controllerTransferFailure("resultTransferInvalid")
			}
			imageBytes += len(decoded)
			if imageBytes > controllerImageLimit {
				return nil, controllerTransferFailure("resultTransferTooLarge")
			}
		default:
			return nil, controllerTransferFailure("resultTransferInvalid")
		}
		for key := range block {
			if !allowed[key] {
				return nil, controllerTransferFailure("resultTransferInvalid")
			}
		}
		if annotations, ok := block["annotations"]; ok && !controllerAnnotations(annotations) {
			return nil, controllerTransferFailure("resultTransferInvalid")
		}
		out = append(out, block)
	}
	return out, nil
}
func controllerAnnotations(raw json.RawMessage) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return false
	}
	for key, value := range fields {
		switch key {
		case "audience":
			var roles []string
			if json.Unmarshal(value, &roles) != nil || len(roles) > 2 {
				return false
			}
			for _, role := range roles {
				if role != "user" && role != "assistant" {
					return false
				}
			}
		case "priority":
			var n float64
			if json.Unmarshal(value, &n) != nil || math.IsNaN(n) || n < 0 || n > 1 {
				return false
			}
		case "lastModified":
			var date string
			if json.Unmarshal(value, &date) != nil || len(date) > 64 {
				return false
			}
			if _, e := time.Parse(time.RFC3339, date); e != nil {
				return false
			}
		default:
			return false
		}
	}
	return true
}

type controllerResultChunk struct {
	Type           string `json:"type"`
	RequestID      string `json:"requestId"`
	SessionID      string `json:"sessionId"`
	BrokerEpoch    string `json:"brokerEpoch"`
	ChannelEpoch   string `json:"channelEpoch"`
	ScopeHash      string `json:"scopeHash"`
	DeadlineUnixMS int64  `json:"deadlineUnixMs"`
	Sequence       int    `json:"sequence"`
	Count          int    `json:"count"`
	TotalBytes     int    `json:"totalBytes"`
	SHA256         string `json:"sha256"`
	Data           string `json:"data"`
}

func controllerChunk(r *controllerRequest, raw []byte, digest string, sequence int) controllerResultChunk {
	start := sequence * controllerChunkBytes
	end := min(start+controllerChunkBytes, len(raw))
	return controllerResultChunk{Type: "controllerResultChunk", RequestID: r.RequestID, SessionID: r.SessionID, BrokerEpoch: r.BrokerEpoch, ChannelEpoch: r.ChannelEpoch, ScopeHash: r.ScopeHash, DeadlineUnixMS: r.Deadline, Sequence: sequence, Count: (len(raw) + controllerChunkBytes - 1) / controllerChunkBytes, TotalBytes: len(raw), SHA256: digest, Data: base64.StdEncoding.EncodeToString(raw[start:end])}
}
func controllerResultDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
