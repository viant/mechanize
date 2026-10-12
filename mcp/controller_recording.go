package mcp

import (
	"github.com/viant/mechanize/engine/recording"
	"strings"
)

// Recording journals may contain action values and reasons from transports.
// Only this finite metadata projection crosses the browser controller boundary.
func validControllerRecordingStatus(s recording.Status) bool {
	if len(s.RecordingID) < 1 || len(s.RecordingID) > 96 || s.PersistedEvents < 0 || s.PersistedEvents > 4096 || s.LastSequence > 9007199254740991 {
		return false
	}
	for _, c := range s.RecordingID {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	switch s.State {
	case "starting", "recording", "paused", "stopped", "interrupted":
	default:
		return false
	}
	reason := s.Reason
	if strings.HasSuffix(reason, ";teardownUnconfirmed") {
		reason = strings.TrimSuffix(reason, ";teardownUnconfirmed")
		switch reason {
		case "captureInterrupted", "controlUnconfirmed", "persistenceUnconfirmed", "drainInterrupted":
		default:
			return false
		}
	}
	switch reason {
	case "", "startUnconfirmed", "captureInterrupted", "controlUnconfirmed", "persistenceUnconfirmed", "drainInterrupted", "coverageGap", "teardownUnconfirmed", "liveStateUnavailable", "captureOwnerEnded":
		return true
	}
	return false
}
