//go:build darwin && cgo

package nativepeer

import (
	"encoding/json"
	"io"
	"os"
	"strconv"
	"testing"
)

// Read-only opt-in: verifies an already-running process. It does not launch
// Chrome, connect to its tabs, load enrollment credentials or mint socket trust.
func TestExistingChromeRunningImageProof(t *testing.T) {
	rawPID := os.Getenv("MECHANIZE_EXISTING_CHROME_PID")
	if rawPID == "" {
		t.Skip("existing Chrome PID metadata proof is opt-in")
	}
	pid, e := strconv.Atoi(rawPID)
	if e != nil || pid <= 1 {
		t.Fatal("invalid fixture PID")
	}
	file, e := os.Open(os.Getenv("MECHANIZE_EXISTING_CHROME_POLICY"))
	if e != nil {
		t.Fatal("private config unavailable")
	}
	defer file.Close()
	var config struct {
		ProcessTrust struct {
			ExpectedUID       uint32 `json:"expectedUID"`
			ChromeExecutable  string `json:"chromeExecutable"`
			ChromeRequirement string `json:"chromeRequirement"`
		} `json:"processTrust"`
	}
	if json.NewDecoder(io.LimitReader(file, 16384)).Decode(&config) != nil {
		t.Fatal("public process policy unavailable")
	}
	policy := ChromeProcessPolicy{ExpectedUID: config.ProcessTrust.ExpectedUID, ChromeExecutable: config.ProcessTrust.ChromeExecutable, ChromeRequirement: config.ProcessTrust.ChromeRequirement}
	before, e := inspectProcessParent(pid)
	if e != nil || before.identity.UID != policy.ExpectedUID || before.identity.StartToken == "" {
		t.Fatal("kernel identity unavailable")
	}
	proof, e := verifyChromeAncestorImage(policy, before, verifyExecutable, verifyDynamicProcess)
	if e != nil {
		t.Fatal("running image verification refused")
	}
	if verifyDynamicProcess(pid, policy.ChromeRequirement) != nil || verifyDynamicProcess(pid, GoogleChromeSignerRequirement) != nil || proof() != nil {
		t.Fatal("dynamic original/vendor signature or image stability refused")
	}
	after, e := inspectProcessParent(pid)
	if e != nil || after != before {
		t.Fatal("kernel identity changed")
	}
	// The constructor's existing canonical requirement stays unchanged. This
	// fixture reports its current availability without treating it as running proof.
	t.Logf("existingProcessOriginalPin=true vendor=true stableKernelIdentity=true canonicalOriginalPin=%t", VerifyChromeExecutable(policy.ChromeExecutable, Options{ExpectedUID: policy.ExpectedUID, DesignatedRequirement: policy.ChromeRequirement}) == nil)
}
