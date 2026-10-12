package nativepeer

import (
	"context"
	"path/filepath"
	"strings"
)

// ChromeLaunchDiagnostic is metadata only, never evidence admitted as trust.
// No executable path, PID, start token, argument, error or credential is returned.
type ChromeLaunchDiagnostic struct {
	HostPIDMatches          bool   `json:"hostPIDMatches"`
	HostStartMatches        bool   `json:"hostStartMatches"`
	HostUIDMatches          bool   `json:"hostUIDMatches"`
	ParentPIDMatches        bool   `json:"parentPIDMatches"`
	ParentStartMatches      bool   `json:"parentStartMatches"`
	ParentKind              string `json:"parentKind"`
	ParentPathMatchesPolicy bool   `json:"parentPathMatchesPolicy"`
	ParentUIDMatches        bool   `json:"parentUIDMatches"`
	DynamicParentPinMatches bool   `json:"dynamicParentPinMatches"`
	AncestryDepth           int    `json:"ancestryDepth"`
	AncestryClass           string `json:"ancestryClass"`
}

func InspectChromeLaunchDiagnostic(ctx context.Context, pid int, policy ChromeProcessPolicy) ChromeLaunchDiagnostic {
	return inspectChromeLaunchDiagnostic(ctx, pid, policy, inspectProcessParent, verifyDynamicProcess)
}
func diagnosticParentKind(path, chrome string) string {
	if path == chrome {
		return "chromeMain"
	}
	if path == "/sbin/launchd" {
		return "launchd"
	}
	mainSuffix := string(filepath.Separator) + "Contents/MacOS/Google Chrome"
	if strings.HasSuffix(chrome, mainSuffix) {
		root := strings.TrimSuffix(chrome, mainSuffix)
		if strings.HasPrefix(path, root+"/Contents/Frameworks/") {
			switch filepath.Base(path) {
			case "Google Chrome Helper", "Google Chrome Helper (Renderer)", "Google Chrome Helper (GPU)", "Google Chrome Helper (Plugin)":
				return "chromeHelper"
			}
		}
	}
	return "other"
}
func inspectChromeLaunchDiagnostic(ctx context.Context, pid int, policy ChromeProcessPolicy, inspect func(int) (processParent, error), verify func(int, string) error) ChromeLaunchDiagnostic {
	result := ChromeLaunchDiagnostic{ParentKind: "other", AncestryClass: "unavailable"}
	if ctx.Err() != nil || validateChromePolicy(policy) != nil || pid <= 1 {
		return result
	}
	host, err := inspect(pid)
	if err != nil {
		return result
	}
	result.HostPIDMatches = host.identity.PID == pid
	result.HostUIDMatches = host.identity.UID == policy.ExpectedUID
	nodes := []processParent{host}
	seen := map[int]bool{pid: true}
	next := host.parentPID
	bound := policy.MaximumAncestors
	if bound == 0 {
		bound = 8
	}
	for depth := 0; depth < bound; depth++ {
		if ctx.Err() != nil || next <= 0 {
			break
		}
		if seen[next] {
			result.AncestryClass = "cycle"
			break
		}
		seen[next] = true
		parent, e := inspect(next)
		if e != nil {
			break
		}
		result.AncestryDepth++
		nodes = append(nodes, parent)
		if depth == 0 {
			result.ParentPIDMatches = parent.identity.PID == next
			result.ParentUIDMatches = parent.identity.UID == policy.ExpectedUID
			result.ParentKind = diagnosticParentKind(parent.identity.Executable, policy.ChromeExecutable)
			result.ParentPathMatchesPolicy = parent.identity.Executable == policy.ChromeExecutable
			result.DynamicParentPinMatches = verify(next, policy.ChromeRequirement) == nil
		}
		if parent.identity.Executable == policy.ChromeExecutable {
			result.AncestryClass = "chromeWithinBound"
			break
		}
		result.AncestryClass = "limitReached"
		next = parent.parentPID
	}
	for index, node := range nodes {
		current, e := inspect(node.identity.PID)
		stable := e == nil && current == node && node.identity.StartToken != ""
		if index == 0 {
			result.HostStartMatches = stable
		}
		if index == 1 {
			result.ParentStartMatches = stable
		}
		if !stable {
			result.AncestryClass = "identityChanged"
		}
	}
	return result
}
