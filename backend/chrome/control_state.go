package chrome

// controlTarget excludes mutable document generation and lease generation. Each
// record owns one exact authority; generation checks remain in sameControl.
type controlTarget struct {
	owner, client, profile, browser, document string
	tab, frame                                int
}
type controlRecord struct {
	authority         *ControlAuthority
	retiring          bool
	navigationRetired *ControlAuthority
}

func controlTargetOf(a ControlAuthority) controlTarget {
	d := a.Document.Identity
	return controlTarget{a.Owner, a.ClientID, d.ProfileChannel, d.BrowserInstance, d.DocumentID, d.TabID, d.FrameID}
}

// All control record access requires controlMu.
func (g *Gateway) controlRecordLocked(a ControlAuthority) *controlRecord {
	if record := g.controls[controlTargetOf(a)]; record != nil {
		return record
	}
	for _, record := range g.controls {
		if sameControlExecutorTarget(record.authority.Document.Identity, a.Document.Identity) {
			return record
		}
	}
	return nil
}
func (g *Gateway) setControlLocked(a ControlAuthority) *controlRecord {
	if g.controls == nil {
		g.controls = make(map[controlTarget]*controlRecord)
	}
	key := controlTargetOf(a)
	record := g.controls[key]
	if record == nil {
		record = &controlRecord{}
		g.controls[key] = record
	}
	copy := a
	record.authority = &copy
	return record
}
func (g *Gateway) clearControlLocked(a ControlAuthority) bool {
	record := g.controlRecordLocked(a)
	if record == nil || record.authority == nil || !sameControl(*record.authority, a) {
		return false
	}
	delete(g.controls, controlTargetOf(a))
	return true
}
