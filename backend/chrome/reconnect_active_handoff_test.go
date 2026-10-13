package chrome

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestReconnectActiveHandoffAuditIsClosedMetadata(t *testing.T) {
	scope := strings.Repeat("a", 64)
	for _, mode := range []string{"legacyV6", "activeV1", "foreignAuditScope", "foreignCandidateScope", "wrongOldEpoch", "nullAudit", "extraAudit", "mixedRecovery", "nullRecovery", "nullHistory", "emptyFormat", "unknownFormat", "recursiveVersion", "missingCandidate", "duplicateCandidate", "historicalAdmission", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			old := ReconnectFence{"original", "original", scope}
			next := ReconnectFence{"fresh", "fresh", scope}
			partial := ReconnectFence{"partial", "partial", scope}
			audit := map[string]any{"digest": strings.Repeat("d", 64), "bytes": 250000, "format": "legacy", "version": 6, "phase": "pending", "nonce": strings.Repeat("c", 64), "oldFence": old, "newFence": partial}
			value := map[string]any{"format": "activeHandoff", "version": 1, "phase": "pending", "nonce": strings.Repeat("b", 64), "oldFence": old, "newFence": next, "history": []any{}, "audit": audit, "recoveryFences": []ReconnectFence{old, partial, next}}
			switch mode {
			case "activeV1":
				audit["format"] = "activeHandoff"
				audit["version"] = 1
			case "foreignAuditScope":
				audit["oldFence"] = ReconnectFence{"original", "original", strings.Repeat("f", 64)}
			case "foreignCandidateScope":
				value["recoveryFences"] = []ReconnectFence{next, {"foreign", "foreign", strings.Repeat("f", 64)}}
			case "wrongOldEpoch":
				audit["oldFence"] = ReconnectFence{"unrelated", "unrelated", scope}
			case "nullAudit":
				value["audit"] = nil
			case "extraAudit":
				audit["authority"] = "forbidden"
			case "mixedRecovery":
				value["recovery"] = map[string]any{"kind": "verifiedCurrentDocuments", "originalPending": map[string]any{}}
			case "nullRecovery":
				value["recovery"] = nil
			case "nullHistory":
				value["history"] = nil
			case "emptyFormat":
				value["format"] = ""
			case "unknownFormat":
				value["format"] = "unknown"
			case "recursiveVersion":
				value["version"] = 6
			case "missingCandidate":
				value["recoveryFences"] = []ReconnectFence{old}
			case "duplicateCandidate":
				value["recoveryFences"] = []ReconnectFence{next, next}
			case "historicalAdmission":
				value["history"] = []any{map[string]any{"nonce": strings.Repeat("9", 64), "oldFence": old, "newFence": next, "executors": []any{}}}
			case "oversize":
				audit["bytes"] = MaxFrameBytes + 1
			}
			raw, _ := json.Marshal(value)
			fences, digest, err := reconnectBindingLineage(raw, scope)
			if mode != "legacyV6" && mode != "activeV1" {
				if err == nil {
					t.Fatal("invalid active metadata admitted")
				}
				return
			}
			sum := sha256.Sum256(raw)
			if err != nil || len(fences) != 3 || digest != hex.EncodeToString(sum[:]) {
				t.Fatal("bounded active handoff or exact bytes refused", err)
			}
		})
	}
}
