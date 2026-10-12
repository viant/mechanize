package chrome

import "testing"

func TestReportedExtensionVersionRejectsNonVersionMetadata(t *testing.T) {
	for _, value := range []string{"0.1.45", "1", "65535.65535.65535.65535"} {
		if reportedExtensionVersion(value) != value {
			t.Fatalf("valid version rejected: %q", value)
		}
	}
	for _, value := range []string{"", "0", "0.0.0.0", "01.2", "65536", "1.2.3.4.5", "1..2", "1.2-private-canary", "1.2\n", "+1", "private-canary"} {
		if reportedExtensionVersion(value) != "" {
			t.Fatal("non-version handshake metadata exposed")
		}
	}
}

func TestControllerCatalogCapacityFromBoundedExtensionVersion(t *testing.T) {
	for _, v := range []string{"", "0.1.62", "0.1.62.65535", "0.1", "0.0.999", "0.1.063", "0.1.63-private-canary", "1.2.3.4.5"} {
		if controllerCatalogLimit(v) != 32 {
			t.Fatal("old or unknown receiver upgraded", v)
		}
	}
	for _, v := range []string{"0.1.63", "0.1.63.1", "0.1.64", "0.2.0", "1"} {
		if controllerCatalogLimit(v) != 64 {
			t.Fatal("new receiver downgraded", v)
		}
	}
}
