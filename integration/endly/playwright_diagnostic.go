package endly

// PlaywrightDiagnostic is bounded operational metadata from one original
// execution. It carries no arguments, selectors, pages, paths or provider text.
type PlaywrightDiagnostic struct {
	Phase          string `json:"phase"`
	Callbacks      int    `json:"callbacks"`
	PeerChecks     int    `json:"peerChecks"`
	PeerMs         int64  `json:"peerMs"`
	IdentityChecks int    `json:"identityChecks"`
	ElapsedMs      int64  `json:"elapsedMs"`
	LastCallback   string `json:"lastCallback"`
	LastMethod     string `json:"lastMethod"`
}

type playwrightDiagnosticFailure interface{ PlaywrightExecutionDiagnostic() PlaywrightDiagnostic }

func (d PlaywrightDiagnostic) valid(code string) bool {
	if d.Phase != code || len(code) < 10 || code[:10] != "playwright" || d.Callbacks < 0 || d.Callbacks > 65536 || d.PeerChecks < 0 || d.PeerChecks > 65536 || d.IdentityChecks < 0 || d.IdentityChecks > 65536 || d.PeerMs < 0 || d.PeerMs > 120000 || d.ElapsedMs < 0 || d.ElapsedMs > 120000 {
		return false
	}
	switch d.LastCallback {
	case "none", "admit", "current", "relay.open", "relay.send", "relay.redact", "relay.close", "intent.confirm", "receipt.persist":
	default:
		return false
	}
	switch d.LastMethod {
	case "none", "Page.enable", "Page.getFrameTree", "Page.setLifecycleEventsEnabled", "Page.addScriptToEvaluateOnNewDocument", "Page.createIsolatedWorld", "Page.bringToFront", "Page.getLayoutMetrics", "Runtime.enable", "Runtime.evaluate", "Runtime.callFunctionOn", "Runtime.getProperties", "Runtime.releaseObject", "Runtime.releaseObjectGroup", "Runtime.runIfWaitingForDebugger", "DOM.enable", "DOM.getDocument", "DOM.describeNode", "DOM.resolveNode", "DOM.getContentQuads", "DOM.getBoxModel", "DOM.scrollIntoViewIfNeeded", "DOM.getNodeForLocation", "Log.enable", "Inspector.enable", "Network.enable", "Network.setCacheDisabled", "Network.setBypassServiceWorker", "Emulation.setFocusEmulationEnabled", "Emulation.setEmulatedMedia", "Target.setAutoAttach", "Input.dispatchMouseEvent", "Input.dispatchKeyEvent", "Input.insertText":
		return true
	}
	return false
}
