package chrome

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReconnectRecoveryDiagnosticClosedCounts(t *testing.T) {
	frame := func(counts string) []byte {
		return []byte(`{"reconnectPhase":"inspect","reconnectReason":"rendererUnavailable","reconnectRecovery":` + counts + `,"message":"private-canary","origin":"https://private.example"}`)
	}
	valid := `{"missingLiveReceipts":1,"unknownLiveReceipts":2,"unavailableExecutors":200,"privateSources":0}`
	got := closedReconnectRecoveryAttention(frame(valid), "storedFenceMismatch")
	if got == nil || got.MissingLiveReceipts != 1 || got.UnknownLiveReceipts != 2 || got.UnavailableExecutors != 200 || got.PrivateSources != 0 {
		t.Fatal("bounded counters lost", got)
	}
	encoded, err := json.Marshal(got)
	if err != nil || strings.Contains(string(encoded), "private-canary") || strings.Contains(string(encoded), "https://") {
		t.Fatal("projection leaked non-count data")
	}
	for _, counts := range []string{
		`{"missingLiveReceipts":-1,"unknownLiveReceipts":0,"unavailableExecutors":0,"privateSources":0}`,
		`{"missingLiveReceipts":201,"unknownLiveReceipts":0,"unavailableExecutors":0,"privateSources":0}`,
		`{"missingLiveReceipts":1.5,"unknownLiveReceipts":0,"unavailableExecutors":0,"privateSources":0}`,
		`{"missingLiveReceipts":null,"unknownLiveReceipts":0,"unavailableExecutors":0,"privateSources":0}`,
		`{"missingLiveReceipts":0,"unknownLiveReceipts":0,"unavailableExecutors":0}`,
		`{"missingLiveReceipts":0,"unknownLiveReceipts":0,"unavailableExecutors":0,"privateSources":0,"documentId":"private-canary"}`,
		`{"missingLiveReceipts":0,"unknownLiveReceipts":0,"unavailableExecutors":0,"privateSources":0,"privateSources":1}`,
	} {
		if closedReconnectRecoveryAttention(frame(counts), "storedFenceMismatch") != nil {
			t.Fatal("invalid counts admitted")
		}
	}
	if closedReconnectRecoveryAttention(frame(valid), "executorBindingFailed") != nil {
		t.Fatal("unrelated attention admitted")
	}
	for _, replacement := range []string{`"reconnectReason":"none"`, `"reconnectReason":"private-canary"`} {
		raw := strings.Replace(string(frame(valid)), `"reconnectReason":"rendererUnavailable"`, replacement, 1)
		if closedReconnectRecoveryAttention([]byte(raw), "storedFenceMismatch") != nil {
			t.Fatal("unqualified refusal admitted")
		}
	}
}
