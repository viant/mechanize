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
