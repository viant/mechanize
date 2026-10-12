package chrome

// BrowserSetup contains only static guidance derived from owned channel flags.
// It cannot prove that an extension is installed when no channel has connected,
// and it never loads Chrome profile files, credential resources or page content.
type BrowserSetup struct {
	State      string `json:"state"`
	NextAction string `json:"nextAction"`
}

func (s BrowserStatus) SetupStatus() BrowserSetup {
	if s.AttentionCode == "chromeProcessUnqualified" {
		return BrowserSetup{"qualificationRequired", "Chrome process verification failed. Native administration remains available. Review and explicitly reload verified enrollment/configuration before restarting the browser bridge; preserve existing unknown effects."}
	}
	if !s.Available || len(s.Channels) == 0 {
		return BrowserSetup{"enrollmentRequired", "If Mechanize is not already loaded, load it in the intended Chrome profile. Provide its Chrome-reported extension ID and complete local native-host enrollment."}
	}
	// Never suggest reconnecting or re-enrolling around an unknown effect.
	for _, c := range s.Channels {
		if c.UnknownCount > 0 && (c.VisibilityUnknownCount != c.UnknownCount || !c.Connected || !c.ProcessQualified || !c.ScopeQualified || !c.ExecutorQualified) {
			return BrowserSetup{"recoveryRequired", "Inspect and reconcile the existing unknown effects before reconnecting or changing enrollment."}
		}
	}
	for _, c := range s.Channels {
		if c.PendingCount > 0 {
			return BrowserSetup{"operationPending", "Inspect the existing pending operation; do not replay it or restart the channel."}
		}
	}
	connected := false
	qualified := false
	ready := false
	for _, c := range s.Channels {
		if !c.Connected {
			continue
		}
		connected = true
		if c.FixtureOnly || !c.ProcessQualified || !c.ScopeQualified || !c.ExecutorQualified || !c.InventoryComplete || c.AttentionCode != "" {
			continue
		}
		qualified = true
		if c.DocumentCount > 0 {
			ready = true
		}
	}
	if ready {
		for _, c := range s.Channels {
			if c.VisibilityUnknownCount > 0 {
				return BrowserSetup{"ready", "Fresh target-bound DOM operations are available. Original tab-visibility outcomes remain UNKNOWN; do not replay them. Native focus and ordinary consent checks still apply."}
			}
		}
		return BrowserSetup{"ready", "Use an owned qualified document through Mechanize MCP; ordinary action consent and scope checks still apply."}
	}
	if qualified {
		return BrowserSetup{"pageRequired", "Open a page within the enrolled origins and refresh browser status."}
	}
	if connected {
		for _, c := range s.Channels {
			if !c.Connected {
				continue
			}
			switch c.AttentionCode {
			case "websiteScopeMismatch":
				return BrowserSetup{"websiteScopeMismatch", "Website access differs between Mechanize and the Chrome extension. Review the selected website access in both before reconnecting."}
			case "lifecycleInhibited":
				return BrowserSetup{"recoveryRequired", "Chrome setup is held by an unfinished update or recovery. Resume that operation before reconnecting; retain its recovery records."}
			}
		}
		return BrowserSetup{"qualificationRequired", "Inspect the channel qualification flags and attention code; preserve enrollment and do not bypass failed trust checks."}
	}
	return BrowserSetup{"connectionRequired", "Open the Mechanize extension options in the intended profile and connect using the locally supplied channel and browser IDs."}
}
