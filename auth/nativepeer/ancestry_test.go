package nativepeer

import (
	"context"
	"errors"
	"fmt"
	"github.com/viant/mechanize/session"
	"strings"
	"testing"
)

func ancestryFixture() (ChromeProcessPolicy, map[int]processParent) {
	policy := ChromeProcessPolicy{ExpectedUID: 501, NativeHostExecutable: "/fixture/native-host", NativeHostRequirement: "host pin", ChromeExecutable: "/fixture/Chrome", ChromeRequirement: "Chrome pin", MaximumAncestors: 3}
	nodes := map[int]processParent{10: {identity: session.ProcessIdentity{PID: 10, UID: 501, Executable: policy.NativeHostExecutable, StartToken: "host-start"}, parentPID: 20}, 20: {identity: session.ProcessIdentity{PID: 20, UID: 501, Executable: policy.ChromeExecutable, StartToken: "chrome-start"}, parentPID: 1}}
	return policy, nodes
}
func TestChromeAncestryEvidenceDoesNotMintProfileOrExecutorTrust(t *testing.T) {
	p, nodes := ancestryFixture()
	checks := map[int]string{}
	evidence, err := verifyChromeProcess(context.Background(), 10, p, func(pid int) (processParent, error) { return nodes[pid], nil }, func(pid int, requirement string) error { checks[pid] = requirement; return nil })
	if err != nil || evidence.NativeHost.PID != 10 || evidence.ChromeParent.PID != 20 || checks[10] != p.NativeHostRequirement || checks[20] != p.ChromeRequirement {
		t.Fatalf("ancestry: %+v %v", evidence, err)
	}
	if evidence.KernelPeerQualified || evidence.ProfileQualified || evidence.ExecutorQualified {
		t.Fatal("PID ancestry minted socket/profile/executor authority")
	}
}
func TestChromeAncestryRejectsMutationReuseMissingAndSignatureFailures(t *testing.T) {
	for _, name := range []string{"host UID", "host image", "parent UID", "parent image", "cycle", "bound", "changed start", "changed parent", "signature", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			p, nodes := ancestryFixture()
			ctx := context.Background()
			reads := map[int]int{}
			switch name {
			case "host UID":
				n := nodes[10]
				n.identity.UID++
				nodes[10] = n
			case "host image":
				n := nodes[10]
				n.identity.Executable = "/other"
				nodes[10] = n
			case "parent UID":
				n := nodes[20]
				n.identity.UID++
				nodes[20] = n
			case "parent image":
				n := nodes[20]
				n.identity.Executable = "/other"
				nodes[20] = n
			case "cycle":
				n := nodes[20]
				n.identity.Executable = "/other"
				n.parentPID = 10
				nodes[20] = n
			case "bound":
				p.MaximumAncestors = 1
				n := nodes[20]
				n.identity.Executable = "/intermediary"
				n.parentPID = 30
				nodes[20] = n
				nodes[30] = processParent{identity: session.ProcessIdentity{PID: 30, UID: 501, Executable: p.ChromeExecutable, StartToken: "start"}, parentPID: 1}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			_, err := verifyChromeProcess(ctx, 10, p, func(pid int) (processParent, error) {
				reads[pid]++
				n, ok := nodes[pid]
				if !ok {
					return n, errors.New("missing PID")
				}
				if reads[pid] > 1 && name == "changed start" {
					n.identity.StartToken = "replacement"
				}
				if reads[pid] > 1 && name == "changed parent" {
					n.parentPID = 99
				}
				return n, nil
			}, func(int, string) error {
				if name == "signature" {
					return errors.New("signature mismatch")
				}
				return nil
			})
			if err == nil {
				t.Fatal("unqualified ancestry admitted")
			}
		})
	}
}

func TestChromeProcessFailureStagesPreserveChecksAndHideCause(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stage error
	}{
		{"inspect", ErrNativeHostProcessUnavailable}, {"UID", ErrNativeHostUIDUnavailable}, {"image", ErrRunningImageMismatch}, {"hostSignature", ErrNativeHostDynamicSignatureUnavailable}, {"ancestor", ErrChromeAncestryUnavailable}, {"parent", ErrChromeParentUnavailable}, {"chromeSignature", ErrChromeSignatureUnavailable}, {"changed", ErrAncestryChanged}, {"bound", ErrChromeAncestryUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, nodes := ancestryFixture()
			p.MaximumAncestors = 1
			cause := errors.New("private-path-and-token-canary")
			reads := map[int]int{}
			switch tc.name {
			case "UID":
				n := nodes[10]
				n.identity.UID++
				nodes[10] = n
			case "image":
				n := nodes[10]
				n.identity.Executable = "/private-canary"
				nodes[10] = n
			case "parent":
				n := nodes[20]
				n.identity.UID++
				nodes[20] = n
			case "bound":
				n := nodes[20]
				n.identity.Executable = "/intermediary"
				n.parentPID = 30
				nodes[20] = n
			}
			_, err := verifyChromeProcess(context.Background(), 10, p, func(pid int) (processParent, error) {
				reads[pid]++
				if tc.name == "inspect" && pid == 10 || tc.name == "ancestor" && pid == 20 {
					return processParent{}, cause
				}
				n := nodes[pid]
				if tc.name == "changed" && reads[pid] > 1 {
					n.identity.StartToken = "replacement"
				}
				return n, nil
			}, func(pid int, _ string) error {
				if tc.name == "hostSignature" && pid == 10 || tc.name == "chromeSignature" && pid == 20 {
					return cause
				}
				return nil
			})
			if !errors.Is(err, tc.stage) {
				t.Fatalf("stage mismatch: %v", err)
			}
			if tc.name == "inspect" || tc.name == "ancestor" || tc.name == "hostSignature" || tc.name == "chromeSignature" {
				if !errors.Is(err, cause) {
					t.Fatal("internal cause identity lost")
				}
			}
			for _, format := range []string{"%v", "%+v", "%#v"} {
				if strings.Contains(fmt.Sprintf(format, err), "canary") {
					t.Fatal("private cause exposed")
				}
			}
			if p.MaximumAncestors != 1 || p.ExpectedUID != 501 {
				t.Fatal("policy relaxed")
			}
		})
	}
}
