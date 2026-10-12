package chrome

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestReconnectPendingHistoryCompactionKeepsClosedV5ArchiveAndV4Reference(t *testing.T) {
	scope := strings.Repeat("a", 64)
	for _, mode := range []string{"valid", "foreignArchiveScope", "foreignPredecessorScope", "extraArchiveField", "wrongPredecessorVersion"} {
		t.Run(mode, func(t *testing.T) {
			// The worker stores original v4 bytes verbatim, compacts the completed
			// history prefix, then sends v5 with one shared completed tail. Archive and
			// predecessor references are metadata; they never authorize a fence subset.
			archive := map[string]any{"digest": strings.Repeat("d", 64), "segments": 1, "nonce": strings.Repeat("e", 64), "endFence": ReconnectFence{"prefix-broker", "prefix-channel", scope}}
			reference := map[string]any{"digest": strings.Repeat("f", 64), "bytes": 250000, "version": 4, "nonce": strings.Repeat("c", 64), "oldFence": ReconnectFence{"original-broker", "original-channel", scope}, "newFence": ReconnectFence{"abandoned-broker", "abandoned-channel", scope}}
			value := map[string]any{"version": 5, "phase": "pending", "nonce": strings.Repeat("b", 64), "oldFence": ReconnectFence{"abandoned-broker", "abandoned-channel", scope}, "newFence": ReconnectFence{"current-broker", "current-channel", scope}, "history": []any{map[string]any{"nonce": strings.Repeat("9", 64), "oldFence": ReconnectFence{"prefix-broker", "prefix-channel", scope}, "newFence": ReconnectFence{"original-broker", "original-channel", scope}, "executors": []any{}}}, "archive": archive, "recovery": map[string]any{"kind": "verifiedCurrentDocuments", "originalPendingRef": reference}}
			switch mode {
			case "foreignArchiveScope":
				archive["endFence"] = ReconnectFence{"prefix-broker", "prefix-channel", strings.Repeat("0", 64)}
			case "foreignPredecessorScope":
				reference["oldFence"] = ReconnectFence{"original-broker", "original-channel", strings.Repeat("0", 64)}
			case "extraArchiveField":
				archive["authority"] = "PRIVATE_CANARY"
			case "wrongPredecessorVersion":
				reference["version"] = 3
			}
			raw, _ := json.Marshal(value)
			fences, digest, e := reconnectBindingLineage(raw, scope)
			if mode != "valid" {
				if e == nil {
					t.Fatal("invalid compacted metadata admitted")
				}
				return
			}
			sum := sha256.Sum256(raw)
			if e != nil || digest != hex.EncodeToString(sum[:]) || len(fences) != 4 {
				t.Fatal("compacted pending/reference lineage refused or exact bytes changed", e)
			}
			for _, fence := range fences {
				if fence.ScopeHash != scope {
					t.Fatal("foreign scope admitted")
				}
			}
		})
	}
}
