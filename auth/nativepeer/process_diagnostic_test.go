package nativepeer

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestProcessDiagnosticIsBoundedMetadataNotTrust(t *testing.T) {
	policy, nodes := ancestryFixture()
	policy.MaximumAncestors = 1
	diagnostic := inspectChromeLaunchDiagnostic(context.Background(), 10, policy, func(pid int) (processParent, error) { return nodes[pid], nil }, func(int, string) error { return nil })
	if diagnostic.ParentKind != "chromeMain" || !diagnostic.HostPIDMatches || !diagnostic.HostStartMatches || !diagnostic.ParentStartMatches || !diagnostic.DynamicParentPinMatches || diagnostic.AncestryDepth != 1 || diagnostic.AncestryClass != "chromeWithinBound" {
		t.Fatal("metadata classification failed")
	}
	n := nodes[20]
	n.identity.Executable = "/private-path-canary"
	n.parentPID = 30
	nodes[20] = n
	diagnostic = inspectChromeLaunchDiagnostic(context.Background(), 10, policy, func(pid int) (processParent, error) {
		if pid == 30 {
			t.Fatal("diagnostic relaxed ancestry bound")
		}
		return nodes[pid], nil
	}, func(int, string) error { return errors.New("private-error-canary") })
	raw, _ := json.Marshal(diagnostic)
	if strings.Contains(string(raw), "canary") || diagnostic.ParentKind != "other" || diagnostic.DynamicParentPinMatches || diagnostic.AncestryClass != "limitReached" {
		t.Fatal("private data escaped or class incorrect")
	}
	if _, err := verifyChromeProcess(context.Background(), 10, policy, func(pid int) (processParent, error) { return nodes[pid], nil }, func(int, string) error { return nil }); err == nil {
		t.Fatal("diagnostic enabled otherwise refused trust")
	}
}
func TestDiagnosticParentKindsAreClosed(t *testing.T) {
	chrome := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	for path, kind := range map[string]string{chrome: "chromeMain", "/sbin/launchd": "launchd", "/Applications/Google Chrome.app/Contents/Frameworks/Helpers/Google Chrome Helper (Renderer)": "chromeHelper", "/elsewhere/Google Chrome Helper": "other", "/private-canary": "other"} {
		if diagnosticParentKind(path, chrome) != kind {
			t.Fatal("incorrect parent kind")
		}
	}
}

func TestLaunchdDiagnosticDoesNotPermitLaunchdAncestry(t *testing.T) {
	policy, nodes := ancestryFixture()
	policy.MaximumAncestors = 1
	host := nodes[10]
	host.parentPID = 1
	nodes[10] = host
	parent := nodes[20]
	parent.identity.PID = 1
	parent.identity.UID = 0
	parent.identity.Executable = "/sbin/launchd"
	parent.parentPID = 0
	nodes[1] = parent
	inspect := func(pid int) (processParent, error) { return nodes[pid], nil }
	result := inspectChromeLaunchDiagnostic(context.Background(), 10, policy, inspect, func(int, string) error { return errors.New("not Chrome") })
	if result.ParentKind != "launchd" || result.ParentUIDMatches || result.ParentPathMatchesPolicy || result.DynamicParentPinMatches {
		t.Fatal("launchd metadata classification wrong")
	}
	if _, e := verifyChromeProcess(context.Background(), 10, policy, inspect, func(int, string) error { return nil }); e == nil {
		t.Fatal("diagnostic relaxed launchd refusal")
	}
}
