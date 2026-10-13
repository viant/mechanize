package script

// CapabilityUnavailableError reports a missing qualified route. Its fields
// come from the closed action registry, never a selector or source literal.
type CapabilityUnavailableError struct {
	Action, Surface, Capability string
	Locator                     string
	Alternatives                []string
}

func (e *CapabilityUnavailableError) Error() string {
	return "requested operation capability is unavailable"
}

// LocatorCapability names the closed selector contract, never a selector value.
func LocatorCapability(strategy string) string {
	return map[string]string{"role": "roleLocator", "id": "idLocator", "name": "nameLocator", "text": "textLocator", "label": "labelRelationships", "testId": "testIdLocator"}[strategy]
}
