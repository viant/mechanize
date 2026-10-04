package record

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/session"
)

// RecordEvent is the common redacted native/web lineage envelope. Capture is
// evidence, never automatic approval or a portable target qualification.
type RecordEvent struct {
	EventSurface       string            `json:"eventSurface"`
	RecordingID        string            `json:"recordingId"`
	Sequence           uint64            `json:"sequence"`
	TimestampUnixMS    int64             `json:"timestampUnixMs"`
	Identity           *chrome.Identity  `json:"identity,omitempty"`
	NativeIdentity     *NativeIdentity   `json:"nativeIdentity,omitempty"`
	NativeTarget       *NativeTarget     `json:"target,omitempty"`
	Origin             string            `json:"origin,omitempty"`
	Kind               string            `json:"kind"`
	Locator            *chrome.Locator   `json:"locator,omitempty"`
	Value              *string           `json:"value,omitempty"`
	Redacted           bool              `json:"redacted"`
	ParameterRequired  bool              `json:"parameterRequired,omitempty"`
	ValueTruncated     bool              `json:"valueTruncated,omitempty"`
	SelectorConfidence string            `json:"selectorConfidence,omitempty"`
	Lineage            string            `json:"lineage"`
	Source             string            `json:"source"`
	Trusted            bool              `json:"trusted"`
	SourceAttested     bool              `json:"sourceAttested,omitempty"`
	Reason             string            `json:"reason,omitempty"`
	Bounds             *chrome.DOMBounds `json:"bounds,omitempty"`
}
type NativeIdentity struct {
	UID        uint32 `json:"uid"`
	BundleID   string `json:"bundleID"`
	PID        int32  `json:"pid"`
	StartToken string `json:"startToken"`
	WindowID   string `json:"windowID,omitempty"`
}
type NativeTarget struct {
	Role                string `json:"role"`
	Identifier          string `json:"identifier,omitempty"`
	IdentifierDigest    string `json:"identifierDigest,omitempty"`
	IdentifierQualified bool   `json:"identifierQualified"`
	NameWithheld        bool   `json:"nameWithheld"`
}
type RecordGap = chrome.RecordGap
type RecordBatch struct {
	RecordingID        string        `json:"recordingId"`
	State              string        `json:"state"`
	LeaseExpiresUnixMS int64         `json:"leaseExpiresUnixMs,omitempty"`
	Events             []RecordEvent `json:"events"`
	Gaps               []RecordGap   `json:"gaps"`
	LastSequence       uint64        `json:"lastSequence"`
	Truncated          bool          `json:"truncated"`
}
type Event = RecordEvent
type Batch = RecordBatch
type Gap = RecordGap

func (e RecordEvent) Validate() error {
	if e.Sequence == 0 {
		return errors.New("positive recording sequence required")
	}
	if e.EventSurface != "native" && e.EventSurface != "web" {
		return errors.New("explicit native/web eventSurface required")
	}
	if e.EventSurface == "native" {
		if e.Identity != nil || e.Origin != "" || e.Bounds != nil {
			return errors.New("native event contains web identity facts")
		}
		if e.NativeIdentity != nil {
			if !(session.Scope{AllApplications: true}).AllowsBundle(e.NativeIdentity.BundleID) || e.NativeIdentity.PID <= 0 || e.NativeIdentity.StartToken == "" || len(e.NativeIdentity.StartToken) > 128 {
				return errors.New("native event identity is invalid")
			}
		}
	} else {
		if e.NativeIdentity != nil || e.NativeTarget != nil {
			return errors.New("web event contains native identity facts")
		}
		if e.Origin != "" {
			parsed, err := url.Parse(e.Origin)
			if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
				return errors.New("recorded origin is not an exact HTTP origin")
			}
		}
		if e.Identity != nil {
			if e.Identity.ProfileChannel == "" || e.Identity.BrowserInstance == "" || e.Identity.TabID < 0 || e.Identity.FrameID < 0 || e.Identity.DocumentID == "" || e.Identity.Generation == 0 {
				return errors.New("web recording identity is invalid")
			}
		}
	}
	if e.Locator != nil && (len(e.Locator.Value) > 512 || e.Locator.Name != nil && len(*e.Locator.Name) > 512) {
		return errors.New("recorded locator bound exceeded")
	}
	return nil
}

// FromChromeBatch is the checked compatibility boundary. It does not promote
// isTrusted/source strings into independent provenance attestation.
func FromChromeBatch(batch chrome.RecordBatch) (RecordBatch, error) {
	result := RecordBatch{RecordingID: batch.RecordingID, State: batch.State, LeaseExpiresUnixMS: batch.LeaseExpiresUnixMS, Gaps: append([]RecordGap(nil), batch.Gaps...), LastSequence: batch.LastSequence, Truncated: batch.Truncated}
	for _, old := range batch.Events {
		identity := old.Identity
		var webIdentity *chrome.Identity
		if identity != (chrome.Identity{}) {
			webIdentity = &identity
		}
		event := RecordEvent{EventSurface: "web", RecordingID: old.RecordingID, Sequence: old.Sequence, TimestampUnixMS: old.TimestampUnixMS, Identity: webIdentity, Origin: old.Origin, Kind: old.Kind, Locator: old.Locator, Redacted: old.Redacted, ValueTruncated: old.ValueTruncated, SelectorConfidence: old.SelectorConfidence, Lineage: old.Lineage, Source: old.Source, Trusted: old.Trusted, Reason: old.Reason, Bounds: old.Bounds}
		if event.RecordingID == "" {
			event.RecordingID = batch.RecordingID
		}
		if event.RecordingID != batch.RecordingID {
			return RecordBatch{}, errors.New("legacy Chrome event recording lineage mismatch")
		}
		if err := event.Validate(); err != nil {
			return RecordBatch{}, err
		}
		result.Events = append(result.Events, event)
	}
	return result, nil
}

// DecodeNativeBatch accepts the native transport DTO without importing a native
// backend. Unknown raw text/clipboard fields are rejected; native surface and
// untrusted/unattested defaults are assigned at this checked boundary.
func DecodeNativeBatch(payload []byte) (RecordBatch, error) {
	var batch RecordBatch
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&batch); err != nil {
		return RecordBatch{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return RecordBatch{}, errors.New("native recording contains trailing JSON")
	}
	for i := range batch.Events {
		event := &batch.Events[i]
		if event.EventSurface != "" && event.EventSurface != "native" {
			return RecordBatch{}, errors.New("native transport claimed web event")
		}
		event.EventSurface = "native"
		if event.Value != nil {
			return RecordBatch{}, errors.New("native transport captured raw value text")
		}
		event.Trusted = false
		event.SourceAttested = false
		if event.RecordingID != batch.RecordingID {
			return RecordBatch{}, errors.New("native recording lineage mismatch")
		}
		if err := event.Validate(); err != nil {
			return RecordBatch{}, fmt.Errorf("native recording event: %w", err)
		}
	}
	return batch, nil
}
