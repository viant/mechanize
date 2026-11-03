package model

import "testing"

func TestFocusedWindowScopeRequiresExactNativeProcess(t *testing.T) {
	base := Surface{Kind: "native", BundleID: "com.fixture.editor", ProcessID: 42, ProcessStartToken: "100:1"}
	if err := ValidateNativeRootSurface(base, "focusedWindow"); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"web", "pid", "token", "bad-token"} {
		s := base
		switch mode {
		case "web":
			s.Kind = "web"
		case "pid":
			s.ProcessID = 0
		case "token":
			s.ProcessStartToken = ""
		case "bad-token":
			s.ProcessStartToken = "invalid"
		}
		if ValidateNativeRootSurface(s, "focusedWindow") == nil {
			t.Fatal("invalid focused scope accepted", mode)
		}
	}
}
