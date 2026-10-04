package chrome

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

type recordingExpiryKey struct{}

// WithRecordingLeaseExpiry carries the host-verified consent deadline separately
// from a short RPC timeout. Never populate it from a tool argument.
func WithRecordingLeaseExpiry(ctx context.Context, expiry time.Time) context.Context {
	return context.WithValue(ctx, recordingExpiryKey{}, expiry)
}

func recordingLeaseExpiry(ctx context.Context) (int64, error) {
	expiry := time.Now().Add(30 * time.Second)
	grant, hasGrant := ctx.Value(recordingExpiryKey{}).(time.Time)
	if !hasGrant {
		grant, hasGrant = ctx.Deadline()
	}
	if hasGrant && grant.Before(expiry) {
		expiry = grant
	}
	if !expiry.After(time.Now()) {
		return 0, browserError("recordingExpired", "Live recording consent required", "notDispatched")
	}
	return expiry.UnixMilli(), nil
}

// RecordEvent is already locally redacted. Root persists it through the recording
// Datly component; this package keeps only bounded live scope/lineage state.
type RecordEvent struct {
	RecordingID        string     `json:"recordingId"`
	Sequence           uint64     `json:"sequence"`
	TimestampUnixMS    int64      `json:"timestampUnixMs"`
	Identity           Identity   `json:"identity"`
	Origin             string     `json:"origin"`
	Kind               string     `json:"kind"`
	Locator            *Locator   `json:"locator,omitempty"`
	Value              *string    `json:"value,omitempty"`
	Redacted           bool       `json:"redacted"`
	ValueTruncated     bool       `json:"valueTruncated,omitempty"`
	SelectorConfidence string     `json:"selectorConfidence,omitempty"`
	Lineage            string     `json:"lineage"`
	Source             string     `json:"source"`
	Trusted            bool       `json:"trusted"`
	Reason             string     `json:"reason,omitempty"`
	Bounds             *DOMBounds `json:"bounds,omitempty"`
}
type DOMBounds struct {
	X               float64 `json:"x"`
	Y               float64 `json:"y"`
	Width           float64 `json:"width"`
	Height          float64 `json:"height"`
	CoordinateSpace string  `json:"coordinateSpace"`
}
type RecordGap struct {
	Kind          string `json:"kind"`
	Reason        string `json:"reason"`
	FromSequence  uint64 `json:"fromSequence"`
	ToSequence    uint64 `json:"toSequence"`
	Lost          uint64 `json:"lost"`
	UnknownExtent bool   `json:"unknownExtent,omitempty"`
}
type RecordBatch struct {
	RecordingID        string        `json:"recordingId"`
	State              string        `json:"state"`
	LeaseExpiresUnixMS int64         `json:"leaseExpiresUnixMs,omitempty"`
	Events             []RecordEvent `json:"events"`
	Gaps               []RecordGap   `json:"gaps"`
	LastSequence       uint64        `json:"lastSequence"`
	Truncated          bool          `json:"truncated"`
}
type recording struct {
	mu                   sync.Mutex
	namespace, id, state string
	channel              *channel
	document             Document
	last                 uint64
	gap                  *RecordGap
}

func recordingKey(p auth.Principal, id string) string { return p.Namespace + "\x00" + id }
func (g *Gateway) StartRecording(ctx context.Context, p auth.Principal, surface model.Surface, id string) (RecordBatch, error) {
	if err := authorize(ctx, p, true); err != nil {
		return RecordBatch{}, err
	}
	if id == "" || len(id) > 128 || strings.ContainsRune(id, 0) {
		return RecordBatch{}, browserError("invalidRecording", "Bounded nonempty recording ID required", "notDispatched")
	}
	c, d, err := g.broker.selectDocument(p, surface)
	if err != nil {
		return RecordBatch{}, err
	}
	if !c.grant.Principal.HasScope("desktop:control") {
		return RecordBatch{}, auth.ErrUnauthorized
	}
	key := recordingKey(p, id)
	g.broker.mu.Lock()
	r := g.broker.recordings[key]
	if r == nil {
		if len(g.broker.recordings) >= 128 {
			g.broker.mu.Unlock()
			return RecordBatch{}, browserError("recordingCapacity", "Live recording quota exceeded; persist/export and release old recordings", "notDispatched")
		}
		r = &recording{namespace: p.Namespace, id: id, state: "starting", channel: c, document: d}
		g.broker.recordings[key] = r
	}
	g.broker.mu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.document.DocumentID != d.DocumentID || r.document.ProfileChannel != d.ProfileChannel || r.document.TabID != d.TabID {
		return RecordBatch{}, browserError("recordingConflict", "Recording is bound to another document; stop/export it first", "notDispatched")
	}
	return g.recordControl(ctx, r, "record.start", 0, 64)
}
func (g *Gateway) recording(ctx context.Context, p auth.Principal, id string, control bool) (*recording, error) {
	if err := authorize(ctx, p, control); err != nil {
		return nil, err
	}
	g.broker.mu.Lock()
	r := g.broker.recordings[recordingKey(p, id)]
	g.broker.mu.Unlock()
	if r == nil {
		return nil, auth.ErrUnauthorized
	}
	return r, nil
}
func (g *Gateway) PauseRecording(ctx context.Context, p auth.Principal, id string) (RecordBatch, error) {
	r, e := g.recording(ctx, p, id, true)
	if e != nil {
		return RecordBatch{}, e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return g.recordControl(ctx, r, "record.pause", 0, 64)
}
func (g *Gateway) StopRecording(ctx context.Context, p auth.Principal, id string) (RecordBatch, error) {
	r, e := g.recording(ctx, p, id, true)
	if e != nil {
		return RecordBatch{}, e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return g.recordControl(ctx, r, "record.stop", 0, 64)
}
func (g *Gateway) RecordingEvents(ctx context.Context, p auth.Principal, id string, after uint64, limit int) (RecordBatch, error) {
	r, e := g.recording(ctx, p, id, false)
	if e != nil {
		return RecordBatch{}, e
	}
	if limit < 1 || limit > 64 {
		return RecordBatch{}, browserError("invalidRecording", "Recording limit 1–64 required", "notDispatched")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return g.recordControl(ctx, r, "record.events", after, limit)
}
func (g *Gateway) recordControl(ctx context.Context, r *recording, action string, after uint64, limit int) (RecordBatch, error) {
	g.broker.mu.Lock()
	present := false
	for _, d := range r.channel.documents {
		if d.TabID == r.document.TabID && d.DocumentID == r.document.DocumentID && d.FrameID == r.document.FrameID {
			present = true
			r.document.Generation = d.Generation
			break
		}
	}
	online := r.channel.conn != nil
	g.broker.mu.Unlock()
	if !present || !online {
		if r.gap == nil {
			r.gap = &RecordGap{Kind: "gap", Reason: "documentOrHostLost", FromSequence: r.last + 1, ToSequence: r.last + 1, UnknownExtent: true}
			r.last++
			r.state = "interrupted"
		}
		if action == "record.stop" {
			r.state = "stopUnconfirmed"
		}
		return RecordBatch{RecordingID: r.id, State: r.state, Gaps: []RecordGap{*r.gap}, LastSequence: r.last}, nil
	}
	if r.gap != nil {
		return RecordBatch{RecordingID: r.id, State: r.state, Gaps: []RecordGap{*r.gap}, LastSequence: r.last}, browserError("recordingInterrupted", "Recording has a coverage gap; stop/export and explicitly start a new recording", "notDispatched")
	}
	args := map[string]any{"recordingId": r.id, "afterSequence": after, "limit": limit}
	if action == "record.start" || action == "record.events" && r.state == "recording" {
		expiry, err := recordingLeaseExpiry(ctx)
		if err != nil {
			return RecordBatch{}, err
		}
		args["leaseExpiresUnixMs"] = expiry
	}
	reply, err := g.broker.call(ctx, r.channel, Command{Action: action, Identity: r.document.Identity, Args: args}, false)
	if err != nil {
		return RecordBatch{}, err
	}
	if reply.RecordingID != r.id || len(reply.Events) > limit || len(reply.Gaps) > 8 || (reply.RecordingState != "recording" && reply.RecordingState != "paused" && reply.RecordingState != "stopped") {
		return RecordBatch{}, browserError("invalidRecording", "Recording reply scope/limits/state mismatch", "notDispatched")
	}
	previous := after
	for _, event := range reply.Events {
		if event.Kind != "start" && event.Kind != "pause" && event.Kind != "stop" && event.Kind != "gap" && event.Kind != "press" && event.Kind != "fill" && event.Kind != "select" {
			return RecordBatch{}, browserError("invalidRecording", "Unknown semantic recording event", "notDispatched")
		}
		if event.RecordingID != r.id || event.Sequence <= previous || event.Sequence > reply.LastSequence || event.Identity.ProfileChannel != r.document.ProfileChannel || event.Identity.BrowserInstance != r.document.BrowserInstance || event.Identity.TabID != r.document.TabID || event.Identity.FrameID != r.document.FrameID || event.Identity.DocumentID != r.document.DocumentID || event.Origin != r.document.Origin || event.Source != "chromeDOM" || event.Lineage != fmt.Sprintf("%s:%s:%d", r.id, r.document.DocumentID, event.Sequence) || event.TimestampUnixMS <= 0 || event.TimestampUnixMS > time.Now().Add(time.Minute).UnixMilli() {
			return RecordBatch{}, browserError("invalidRecording", "Recording event identity/lineage mismatch", "notDispatched")
		}
		if event.Redacted && event.Value != nil || event.Value != nil && len(*event.Value) > 4096 {
			return RecordBatch{}, browserError("secretRecording", "Raw secret/oversize recording value rejected", "notDispatched")
		}
		if (event.Kind == "press" || event.Kind == "fill" || event.Kind == "select") && !event.Trusted {
			return RecordBatch{}, browserError("injectedRecording", "Injected events cannot be employee demonstration", "notDispatched")
		}
		previous = event.Sequence
	}
	r.last = max(r.last, reply.LastSequence)
	r.state = reply.RecordingState
	return RecordBatch{RecordingID: r.id, State: r.state, LeaseExpiresUnixMS: reply.RecordingLeaseExpiresUnixMS, Events: reply.Events, Gaps: reply.Gaps, LastSequence: reply.LastSequence, Truncated: reply.Truncated}, nil
}
