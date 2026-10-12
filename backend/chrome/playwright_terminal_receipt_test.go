package chrome

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPlaywrightTerminalReceiptRequiresExactOriginalProof(t *testing.T) {
	c := Command{RequestID: "request", AttemptID: "attempt", Identity: Identity{ProfileChannel: "profile", BrowserInstance: "browser", TabID: 7, DocumentID: "document", Generation: 2}, ControlLease: &Lease{ID: "lease", Generation: 1}, FingerprintVersion: 2, FingerprintSHA256: strings.Repeat("a", 64)}
	for _, mode := range []string{"valid", "request", "attempt", "identity", "lease", "hash", "extra", "state", "possible", "unknown", "dispatched"} {
		t.Run(mode, func(t *testing.T) {
			r := map[string]any{"requestId": c.RequestID, "attemptId": c.AttemptID, "identity": c.Identity, "controlLease": c.ControlLease, "fingerprintVersion": 2, "fingerprintSHA256": c.FingerprintSHA256, "dispatchState": "notDispatched", "effectState": "none"}
			possible := false
			switch mode {
			case "request":
				r["requestId"] = "other"
			case "attempt":
				r["attemptId"] = "other"
			case "identity":
				r["identity"] = Identity{}
			case "lease":
				r["controlLease"] = &Lease{ID: "other", Generation: 1}
			case "hash":
				r["fingerprintSHA256"] = strings.Repeat("b", 64)
			case "extra":
				r["value"] = "PRIVATE-CANARY"
			case "state":
				r["effectState"] = "unknown"
			case "possible":
				possible = true
			case "unknown":
				possible = true
				r["dispatchState"] = "unknown"
				r["effectState"] = "unknown"
			case "dispatched":
				possible = true
				r["dispatchState"] = "dispatched"
				r["effectState"] = "unverified"
			}
			raw, _ := json.Marshal(map[string]any{"receipt": r})
			got := playwrightTerminalReceipt(raw, c, possible)
			valid := mode == "valid" || mode == "unknown" || mode == "dispatched"
			if (got != nil) != valid {
				t.Fatal("receipt proof classification", mode)
			}
			if got != nil && got.DispatchState != r["dispatchState"] {
				t.Fatal("dispatch state changed")
			}
		})
	}
}
