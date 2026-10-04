package host

import (
	"bytes"
	"context"
	"errors"
	"image/jpeg"
	"sync"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/record"
)

// VideoIngestOptions are trusted host bindings, never tool-request callbacks.
// VerifyRecord must verify a pixel-recording grant for this exact scope, owner,
// client and session. Existing observe/capture or AX permission is insufficient.
// Redact must locally classify every pixel frame; a nil result fails closed.
// This opt-in adapter has no native launch/RPC registration or public tool yet.
type VideoIngestOptions struct {
	Artifacts    *ArtifactService
	Principal    auth.Principal
	Binding      auth.ConsentBinding
	Lease        *consent.Lease
	Surface      model.Surface
	RecordingID  string
	MaxDuration  time.Duration
	MaxBytes     int
	MaxFrames    int
	VerifyRecord func(context.Context, auth.Principal, auth.ConsentBinding, model.Surface) error
	Redact       func(context.Context, []byte) ([]byte, error)
}
type VideoFrameIngestor struct {
	mu       sync.Mutex
	options  VideoIngestOptions
	timeline record.VideoTimeline
	started  time.Time
	bytes    int
}

func NewVideoFrameIngestor(o VideoIngestOptions) (*VideoFrameIngestor, error) {
	if o.Artifacts == nil || o.Lease == nil || o.Lease.Context == nil || o.Lease.Release == nil || o.VerifyRecord == nil || o.Redact == nil || o.Principal.ClientID == "" || o.Binding.SessionID == "" || o.Binding.GrantID == "" || !recordingManagerID(o.RecordingID) || o.MaxDuration < time.Second || o.MaxDuration > 15*time.Minute || o.MaxBytes < 1 || o.MaxBytes > 256*1024*1024 || o.MaxFrames < 1 || o.MaxFrames > 3600 {
		return nil, errors.New("complete bounded video record bindings required")
	}
	if err := recordingPrincipal(o.Lease.Context, o.Principal); err != nil {
		return nil, err
	}
	binding, ok := auth.ConsentBindingFromContext(o.Lease.Context)
	if !ok || binding != o.Binding || o.Lease.Context.Err() != nil {
		return nil, auth.ErrUnauthorized
	}
	if expiry, ok := o.Lease.Context.Deadline(); !ok || !expiry.After(time.Now()) {
		return nil, errors.New("bounded live record lease required")
	}
	if _, err := ConsentScope(o.Surface); err != nil {
		return nil, err
	}
	if o.Surface.Kind != "desktop" && o.Surface.Kind != "native" {
		return nil, errors.New("native video scope required")
	}
	if err := o.VerifyRecord(o.Lease.Context, o.Principal, o.Binding, o.Surface); err != nil {
		return nil, err
	}
	return &VideoFrameIngestor{options: o, started: time.Now(), timeline: record.VideoTimeline{RecordingID: o.RecordingID, State: "recording", Frames: []record.VideoFrameEvidence{}}}, nil
}

// Ingest handles trusted local producer bytes. It reserves each sequence once:
// an unknown Datly publication pauses and retains immutable evidence for review.
func (v *VideoFrameIngestor) Ingest(ctx context.Context, stamp record.VideoFrameEvidence, pixels []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	o := v.options
	if err := recordingPrincipal(ctx, o.Principal); err != nil {
		return err
	}
	actual, ok := auth.ConsentBindingFromContext(ctx)
	if !ok || actual != o.Binding {
		return auth.ErrUnauthorized
	}
	if v.timeline.State != "recording" {
		return errors.New("video ingestion paused or stopped")
	}
	if o.Lease.Context.Err() != nil {
		v.pause("consentWithdrawn")
		return o.Lease.Context.Err()
	}
	if time.Since(v.started) >= o.MaxDuration {
		v.pause("durationExpired")
		return errors.New("video duration expired")
	}
	if err := o.VerifyRecord(o.Lease.Context, o.Principal, o.Binding, o.Surface); err != nil {
		v.pause("consentWithdrawn")
		return err
	}
	if stamp.OffsetNanoseconds >= uint64(o.MaxDuration) || stamp.TimestampUnixMS < v.started.Add(-5*time.Second).UnixMilli() || stamp.TimestampUnixMS > time.Now().Add(5*time.Second).UnixMilli() {
		v.pause("invalidVideoLineage")
		return errors.New("video timestamp outside active recording window")
	}
	if len(pixels) == 0 || len(pixels) > 4*1024*1024 || len(v.timeline.Frames) >= o.MaxFrames {
		v.pause("videoCapacity")
		return errors.New("video frame bound exceeded")
	}
	safe, err := o.Redact(o.Lease.Context, pixels)
	if err != nil || len(safe) == 0 {
		v.pause("redactionUnavailable")
		return errors.New("trusted local pixel redaction unavailable")
	}
	if len(safe) > 4*1024*1024 || len(safe) > o.MaxBytes-v.bytes {
		v.pause("videoCapacity")
		return errors.New("video byte bound exceeded")
	}
	config, err := jpeg.DecodeConfig(bytes.NewReader(safe))
	if err != nil || config.Width < 1 || config.Height < 1 || config.Width > 1920 || config.Height > 1920 {
		v.pause("redactionUnavailable")
		return errors.New("bounded redacted JPEG required")
	}
	if _, err = jpeg.Decode(bytes.NewReader(safe)); err != nil {
		v.pause("redactionUnavailable")
		return errors.New("invalid redacted JPEG")
	}
	// Validate timestamp/sequence before persisting any bytes. A temporary reference
	// supplies only structural fields; authoritative fields come from encrypted Put.
	stamp.Artifact.ID = "pending"
	stamp.Artifact.ContentHash = string(bytes.Repeat([]byte{'0'}, 64))
	stamp.Artifact.MediaType = "image/jpeg"
	stamp.Artifact.SizeBytes = len(safe)
	stamp.Artifact.KeyReference = "pending"
	candidate := v.snapshotLocked()
	candidate.Frames = append(candidate.Frames, stamp)
	if err = candidate.Validate(); err != nil {
		v.pause("invalidVideoLineage")
		return err
	}
	callCtx, cancel := context.WithCancel(o.Lease.Context)
	stop := context.AfterFunc(ctx, cancel)
	defer func() { stop(); cancel() }()
	ref, err := o.Artifacts.publishBound(callCtx, o.Principal, "image/jpeg", bytes.NewReader(safe))
	if ref.ID != "" {
		stamp.Artifact = ref
		v.timeline.Frames = append(v.timeline.Frames, stamp)
		v.bytes += len(safe)
	}
	if err != nil {
		v.pause("artifactPublicationFailedOrUnknown")
		return err
	}
	return nil
}
func (v *VideoFrameIngestor) pause(reason string) {
	if v.timeline.State == "recording" {
		v.timeline.State = "paused"
		v.timeline.Gaps = append(v.timeline.Gaps, record.RecordGap{Kind: "gap", Reason: reason, UnknownExtent: true})
	}
}
func (v *VideoFrameIngestor) Pause()  { v.mu.Lock(); defer v.mu.Unlock(); v.pause("manualPause") }
func (v *VideoFrameIngestor) Revoke() { v.mu.Lock(); defer v.mu.Unlock(); v.pause("consentWithdrawn") }

// Stop receives trusted helper cleanup evidence. It does not release the shared
// recording lease: native manager must reap the producer and structured recorder.
func (v *VideoFrameIngestor) Stop(confirmed bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.timeline.State == "stopped" || v.timeline.State == "stopUnconfirmed" && !confirmed {
		return
	}
	if confirmed {
		v.timeline.State = "stopped"
	} else {
		v.timeline.State = "stopUnconfirmed"
		v.timeline.Gaps = append(v.timeline.Gaps, record.RecordGap{Kind: "gap", Reason: "videoStopUnconfirmed", UnknownExtent: true})
	}
}
func (v *VideoFrameIngestor) snapshotLocked() record.VideoTimeline {
	out := v.timeline
	out.Frames = append([]record.VideoFrameEvidence(nil), out.Frames...)
	out.Gaps = append([]record.RecordGap(nil), out.Gaps...)
	return out
}
func (v *VideoFrameIngestor) Snapshot() record.VideoTimeline {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.snapshotLocked()
}
