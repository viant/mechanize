package model

import "fmt"

// ValidateNativeRootSurface keeps focused containers pinned to one exact process.
func ValidateNativeRootSurface(surface Surface, root string) error {
	if surface.Kind != "native" || (root != "menuBar" && root != "focusedElement" && root != "focusedWindow") {
		return fmt.Errorf("supported native root required")
	}
	if root == "focusedWindow" && (surface.ProcessID <= 0 || surface.ProcessStartToken == "" || surface.ValidateProcessIdentity() != nil) {
		return fmt.Errorf("focused window requires exact process identity")
	}
	return nil
}
