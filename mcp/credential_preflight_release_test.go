package mcp

import (
	"strings"
	"testing"
)

func TestCredentialPreflightReleaseIsClosedStatusMetadata(t *testing.T) {
	result := CredentialResult{PreparationID: strings.Repeat("a", 64), State: "needsNativeAction", AttentionCode: "privateInspectionNoCredentialFields"}
	for _, code := range []string{"released", "unconfirmed"} {
		result.PreflightRelease = code
		if !validCredentialResultForTool("mechanize_credential_status", result) {
			t.Fatal("finite no-input release diagnostic rejected")
		}
		for _, name := range []string{"mechanize_credential_apply", "mechanize_credential_prepare", "mechanize_credential_submit"} {
			if validCredentialResultForTool(name, result) {
				t.Fatal("release diagnostic changed unrelated tool contract")
			}
		}
	}
	result.PreflightRelease = "PRIVATE_CANARY"
	if validCredentialResultForTool("mechanize_credential_status", result) {
		t.Fatal("raw diagnostic admitted")
	}
}
