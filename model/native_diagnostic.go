package model

// NativeExecutionFailureCode is a closed presentation-only diagnostic set.
// It grants no input, retry, effect reconciliation or OS permission authority.
func NativeExecutionFailureCode(code string) bool {
	switch code {
	// Correlated helper frame rejections stay distinct from the local
	// staleFramePermit proof. Receipt uncertainty is preserved by the caller.
	case "stalePermit", "windowClickOccluded", "windowHitTestUnavailable", "windowClickUnqualified":
		return true
	case "foregroundAXWindowUnavailable", "foregroundAXWindowChanged", "foregroundAXOwnerMismatch", "foregroundAXFocusUnavailable", "foregroundAXFocusChanged",
		"foregroundGeometryUnavailable", "foregroundGeometryUnbound", "foregroundGeometryAmbiguous",
		"foregroundWindowUnavailable", "foregroundAcquisitionUnavailable", "foregroundChanged", "foregroundNotActive", "foregroundUnavailable", "foregroundRefreshUnavailable", "windowKeyboardUnqualified",
		"foregroundWindowMissing", "foregroundWindowInvisible", "foregroundWindowUnsupportedLayer", "foregroundWindowZeroAlpha", "foregroundWindowAlphaUnavailable", "foregroundWindowAmbiguous",
		"foregroundRaiseWindowMissing", "foregroundRaiseWindowInvisible", "foregroundRaiseWindowAmbiguous":
		return true
	}
	return false
}
