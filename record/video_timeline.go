package record

import (
	"errors"
	"github.com/viant/mechanize/data"
)

// VideoFrameEvidence contains immutable encrypted artifact references, never pixels.
// TimestampUnixMS shares the structured recording wall-clock; OffsetNanoseconds
// is relative to the video capture monotonic origin and detects clock jumps.
type VideoFrameEvidence struct {
	Sequence          uint64                 `json:"sequence"`
	TimestampUnixMS   int64                  `json:"timestampUnixMs"`
	OffsetNanoseconds uint64                 `json:"offsetNanoseconds"`
	DisplayID         uint32                 `json:"displayId"`
	Artifact          data.ArtifactReference `json:"artifact"`
}
type VideoTimeline struct {
	RecordingID   string               `json:"recordingId"`
	State         string               `json:"state"`
	Frames        []VideoFrameEvidence `json:"frames"`
	Gaps          []RecordGap          `json:"gaps,omitempty"`
	AudioCaptured bool                 `json:"audioCaptured"`
}
type EventVideoEvidence struct {
	EventSequence uint64               `json:"eventSequence"`
	EventLineage  string               `json:"eventLineage"`
	Frames        []VideoFrameEvidence `json:"frames,omitempty"`
	Correlation   string               `json:"correlation"`
}

func (v VideoTimeline) Validate() error {
	if v.RecordingID == "" || v.AudioCaptured || len(v.Frames) > 3600 || len(v.Gaps) > 64 {
		return errors.New("bounded silent video timeline required")
	}
	switch v.State {
	case "recording", "paused", "stopped", "stopUnconfirmed":
	default:
		return errors.New("invalid video state")
	}
	var seq, offset uint64
	var timestamp int64
	var total int
	for _, f := range v.Frames {
		if f.Sequence != seq+1 || f.TimestampUnixMS <= 0 || f.TimestampUnixMS < timestamp || f.OffsetNanoseconds < offset || f.OffsetNanoseconds >= 900000000000 || f.Artifact.ID == "" || len(f.Artifact.ContentHash) != 64 || f.Artifact.KeyReference == "" || f.Artifact.MediaType != "image/jpeg" || f.Artifact.SizeBytes <= 0 || f.Artifact.SizeBytes > 4*1024*1024 {
			return errors.New("invalid encrypted video frame lineage")
		}
		for _, r := range f.Artifact.ContentHash {
			if !(r >= 'a' && r <= 'f' || r >= '0' && r <= '9') {
				return errors.New("invalid frame digest")
			}
		}
		if seq > 0 && f.TimestampUnixMS-timestamp != int64(f.OffsetNanoseconds/1000000)-int64(offset/1000000) {
			return errors.New("video wall and monotonic clocks disagree")
		}
		total += f.Artifact.SizeBytes
		if total > 256*1024*1024 {
			return errors.New("video byte bound exceeded")
		}
		seq = f.Sequence
		offset = f.OffsetNanoseconds
		timestamp = f.TimestampUnixMS
	}
	return nil
}

// CorrelateVideo links all displays within a bounded time interval. Temporal
// proximity is context only: it cannot attest an actor, action, or business result.
func CorrelateVideo(events []RecordEvent, video VideoTimeline, toleranceMs int64) ([]EventVideoEvidence, error) {
	if err := video.Validate(); err != nil {
		return nil, err
	}
	if toleranceMs < 0 || toleranceMs > 5000 {
		return nil, errors.New("bounded video correlation tolerance required")
	}
	normalized, err := (Compiler{}).Normalize(events)
	if err != nil {
		return nil, err
	}
	result := make([]EventVideoEvidence, 0, len(normalized))
	for _, event := range normalized {
		if event.RecordingID != video.RecordingID || event.TimestampUnixMS <= 0 || event.Lineage == "" {
			return nil, errors.New("event/video recording identity or timestamp mismatch")
		}
		item := EventVideoEvidence{EventSequence: event.Sequence, EventLineage: event.Lineage, Correlation: "noFrameInInterval"}
		for _, frame := range video.Frames {
			delta := frame.TimestampUnixMS - event.TimestampUnixMS
			if delta >= -toleranceMs && delta <= toleranceMs {
				item.Frames = append(item.Frames, frame)
			}
		}
		if len(item.Frames) > 0 {
			item.Correlation = "temporalContextOnly"
		}
		result = append(result, item)
	}
	return result, nil
}
