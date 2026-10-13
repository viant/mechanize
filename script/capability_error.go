package script

// CapabilityUnavailableError reports a missing qualified route. Its fields
// come from the closed action registry, never a selector or source literal.
type CapabilityUnavailableError struct {
	Action, Surface, Capability string
}

func (e *CapabilityUnavailableError) Error() string {
	return "requested operation capability is unavailable"
}
