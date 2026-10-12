package consent

import "testing"

func TestBrowserScopeRemainsSeparateFromNativeAndExactOrigin(t *testing.T) {
	browser := Scope{Kind: "browser", BundleID: "com.google.Chrome"}
	if browser.Validate() != nil || !browser.Covers(browser) {
		t.Fatal("browser consent invalid")
	}
	for _, s := range []Scope{{Kind: "browser"}, {Kind: "browser", BundleID: "com.other.browser"}, {Kind: "browser", BundleID: "com.google.Chrome", Origin: "https://example.test"}} {
		if s.Validate() == nil {
			t.Fatal("ambiguous browser scope accepted")
		}
	}
	for _, s := range []Scope{{Kind: "origin", Origin: "https://example.test"}, {Kind: "application", BundleID: "com.google.Chrome"}, {Kind: "window", BundleID: "com.google.Chrome", WindowID: "1"}, {Kind: "desktop"}} {
		if browser.Covers(s) {
			t.Fatal("browser scope escaped its operation kind")
		}
	}
}
