// Package chrome connects explicitly enrolled Chrome profiles to the broker.
// It is an action transport, not a workflow scheduler or persistence layer.
package chrome

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"

	"github.com/viant/mechanize/model"
)

const MaxFrameBytes = 256 * 1024

type Identity struct {
	ProfileChannel  string `json:"profileChannel"`
	BrowserInstance string `json:"browserInstance"`
	TabID           int    `json:"tabId"`
	FrameID         int    `json:"frameId"`
	DocumentID      string `json:"documentId"`
	Generation      uint64 `json:"documentGeneration"`
}
type Document struct {
	MutationFingerprintVersion int `json:"mutationFingerprintVersion,omitempty"`
	Identity
	Origin         string `json:"origin"`
	Title          string `json:"title"`
	TitleTruncated bool   `json:"titleTruncated,omitempty"`
	TabHandle      string `json:"tabHandle,omitempty"`
}

func (d Document) QualifiedTabID() string {
	return d.ProfileChannel + "/" + d.BrowserInstance + "/" + strconv.Itoa(d.TabID)
}

type Locator struct {
	Strategy string  `json:"strategy"`
	Value    string  `json:"value"`
	Name     *string `json:"name,omitempty"`
	Exact    bool    `json:"exact"`
}
type Command struct {
	FingerprintVersion int            `json:"fingerprintVersion,omitempty"`
	FingerprintSHA256  string         `json:"fingerprintSHA256,omitempty"`
	ControlLease       *Lease         `json:"controlLease,omitempty"`
	RequestID          string         `json:"requestId"`
	Action             string         `json:"action"`
	Identity           Identity       `json:"identity"`
	BrokerEpoch        string         `json:"brokerEpoch"`
	ChannelEpoch       string         `json:"channelEpoch"`
	ScopeHash          string         `json:"scopeHash"`
	AttemptID          string         `json:"attemptId,omitempty"`
	DeadlineUnixMS     int64          `json:"deadlineUnixMs"`
	Locator            *Locator       `json:"locator,omitempty"`
	Args               map[string]any `json:"args,omitempty"`
}
type Reply struct {
	FingerprintVersion          int                   `json:"fingerprintVersion,omitempty"`
	FingerprintSHA256           string                `json:"fingerprintSHA256,omitempty"`
	ControlLease                *Lease                `json:"controlLease,omitempty"`
	Validated                   bool                  `json:"validated"`
	RetiredAuthorityQuiesced    bool                  `json:"retiredAuthorityQuiesced"`
	RequestID                   string                `json:"requestId"`
	AttemptID                   string                `json:"attemptId"`
	Identity                    Identity              `json:"identity"`
	DispatchState               string                `json:"dispatchState"`
	EffectState                 string                `json:"effectState"`
	ReceiptAvailable            *bool                 `json:"receiptAvailable"`
	Error                       *model.MechanizeError `json:"error"`
	Nodes                       []Node                `json:"nodes"`
	Truncated                   bool                  `json:"truncated"`
	Coverage                    []string              `json:"coverage"`
	Value                       *string               `json:"value"`
	Name                        string                `json:"name"`
	Visible                     *bool                 `json:"visible"`
	Enabled                     *bool                 `json:"enabled"`
	RecordingID                 string                `json:"recordingId"`
	RecordingState              string                `json:"recordingState"`
	RecordingLeaseExpiresUnixMS int64                 `json:"recordingLeaseExpiresUnixMs"`
	Events                      []RecordEvent         `json:"events"`
	Gaps                        []RecordGap           `json:"gaps"`
	LastSequence                uint64                `json:"lastSequence"`
	NewDocument                 *Document             `json:"newDocument"`
	Ready                       bool                  `json:"ready"`
	Active                      bool                  `json:"active"`
}
type Node struct {
	Role    string  `json:"role"`
	Name    string  `json:"name"`
	ID      string  `json:"id"`
	TestID  string  `json:"testId"`
	Visible *bool   `json:"visible"`
	Enabled *bool   `json:"enabled"`
	Value   *string `json:"value"`
}

func browserError(code, message, state string) *model.MechanizeError {
	effect := "none"
	if state == "unknown" {
		effect = "unknown"
	}
	return &model.MechanizeError{Code: code, Message: message, Stage: "browser", DispatchState: state, EffectState: effect}
}
func newID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(value[:])
}
func ReadFrame(reader io.Reader) (json.RawMessage, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := binary.NativeEndian.Uint32(header[:])
	if length == 0 || length > MaxFrameBytes {
		return nil, errors.New("invalid Chrome frame length")
	}
	result := make([]byte, length)
	if _, err := io.ReadFull(reader, result); err != nil {
		return nil, err
	}
	if !utf8.Valid(result) || !json.Valid(result) {
		return nil, errors.New("invalid Chrome UTF-8 JSON")
	}
	return result, nil
}
func WriteFrame(writer io.Writer, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > MaxFrameBytes {
		return errors.New("Chrome frame exceeds cap")
	}
	var header [4]byte
	binary.NativeEndian.PutUint32(header[:], uint32(len(data)))
	for _, part := range [][]byte{header[:], data} {
		for len(part) > 0 {
			n, e := writer.Write(part)
			if e != nil {
				return e
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}
