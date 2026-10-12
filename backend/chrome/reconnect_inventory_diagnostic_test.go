package chrome

import "testing"

func TestReconnectInventoryDiagnosticClosedProjection(t *testing.T) {
	for _, reason := range []string{"rootLifecycleMissing", "rootLifecyclePrerender", "rootLifecycleCached", "rootLifecyclePendingDeletion", "rootLifecycleInvalid", "rootFrameTypeMissing", "rootFrameTypeDenied", "childLifecycleMissing", "childLifecyclePrerender", "childLifecycleCached", "childLifecyclePendingDeletion", "childLifecycleInvalid", "childFrameTypeMissing", "childFrameTypeDenied", "rootFrameTypeOuterMost", "rootFrameTypeSubFrame", "rootFrameTypeFenced", "rootFrameTypeInvalid", "childFrameTypeOuterMost", "childFrameTypeSubFrame", "childFrameTypeFenced", "childFrameTypeInvalid", "inactiveRootParentDenied", "frameParentDocumentMismatch", "nonSetupTab", "inventoryDrift", "pendingNavigation", "discardedTab", "frameDocumentUnavailable", "builtInRootURLDenied", "tabSchemeDenied", "rootFrameURLInvalid", "childFrameURLInvalid", "rootFrameUserinfoDenied", "childFrameUserinfoDenied", "rootFrameSchemeDenied", "rootFrameError", "builtInRootFrameError", "childSourceIdentityUnavailable", "rootFrameOriginNotGranted", "childFrameOriginNotGranted", "rootTabOriginMismatch"} {
		raw := []byte(`{"reconnectPhase":"inventory","reconnectReason":"inventoryChanged","reconnectInventoryReason":"` + reason + `","origin":"https://private.example","message":"private-canary"}`)
		if got := closedReconnectInventoryAttention(raw, "storedFenceMismatch"); got != reason {
			t.Fatalf("reason %s: %q", reason, got)
		}
		if got := closedReconnectInventoryAttention(raw, "executorBindingFailed"); got != "" {
			t.Fatal("unrelated attention admitted", got)
		}
	}
	for _, raw := range []string{
		`{"reconnectPhase":"inventory","reconnectReason":"inventoryChanged","reconnectInventoryReason":"private-canary"}`,
		`{"reconnectPhase":"inventory","reconnectReason":"executorRefused","reconnectInventoryReason":"nonSetupTab"}`,
		`{"reconnectPhase":"private-canary","reconnectReason":"inventoryChanged","reconnectInventoryReason":"nonSetupTab"}`,
		`{"reconnectPhase":"inventory","reconnectReason":"inventoryChanged","reconnectInventoryReason":"nonSetupTab","reconnectInventoryReason":"inventoryDrift"}`,
	} {
		if got := closedReconnectInventoryAttention([]byte(raw), "storedFenceMismatch"); got != "" {
			t.Fatal("unqualified detail admitted", got)
		}
	}
}
