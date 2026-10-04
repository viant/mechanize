package nativepeer

import "testing"

func TestEmptyRequirementDenied(t *testing.T) {
	for _, requirement := range []string{"", "  ", "identifier x\x00"} {
		if verify, err := NewVerifier(Options{DesignatedRequirement: requirement}); err == nil || verify != nil {
			t.Fatal("unconfigured requirement accepted")
		}
	}
}
