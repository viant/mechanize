package nativepeer

import (
	"context"
	"errors"
	"github.com/viant/mechanize/session"
	"testing"
)

func TestQualifiedChromeIdentityRechecksKernelBirthPathUIDAndAncestry(t *testing.T) {
	policy := ChromeProcessPolicy{ExpectedUID: 501, NativeHostExecutable: "/fixture/native", ChromeExecutable: "/fixture/Chrome", NativeHostRequirement: "exact native", ChromeRequirement: "exact Chrome"}
	host := session.ProcessIdentity{PID: 10, UID: 501, StartToken: "host-birth", Executable: policy.NativeHostExecutable}
	chrome := session.ProcessIdentity{PID: 20, UID: 501, StartToken: "chrome-birth", Executable: policy.ChromeExecutable}
	for _, mode := range []string{"current", "pid", "birth", "uid", "path", "parent", "auditChanged", "secondReadChanged", "unqualified", "ancestorMissing", "duplicateAncestor"} {
		t.Run(mode, func(t *testing.T) {
			expected := ChromeProcessEvidence{KernelPeerQualified: true, NativeHost: host, ChromeParent: chrome, Ancestors: []session.ProcessIdentity{chrome}}
			nodes := map[int]processParent{10: {identity: host, parentPID: 20}, 20: {identity: chrome, parentPID: 1}}
			switch mode {
			case "birth":
				n := nodes[10]
				n.identity.StartToken = "reused-birth"
				nodes[10] = n
			case "uid":
				n := nodes[20]
				n.identity.UID++
				nodes[20] = n
			case "path":
				n := nodes[20]
				n.identity.Executable = "/other/Chrome"
				nodes[20] = n
			case "parent":
				n := nodes[10]
				n.parentPID = 30
				nodes[10] = n
			case "unqualified":
				expected.KernelPeerQualified = false
			case "ancestorMissing":
				expected.Ancestors = nil
			case "duplicateAncestor":
				expected.Ancestors = []session.ProcessIdentity{host, chrome}
			}
			audits, reads := 0, 0
			err := verifyQualifiedChromePeerIdentity(context.Background(), policy, expected, func() (int, error) {
				audits++
				if mode == "pid" || mode == "auditChanged" && audits > 1 {
					return 99, nil
				}
				return 10, nil
			}, func(pid int) (processParent, error) {
				reads++
				n := nodes[pid]
				if mode == "secondReadChanged" && reads > 2 {
					n.identity.StartToken = "changed-during-read"
				}
				return n, nil
			})
			if mode == "current" {
				if err != nil || audits != 2 || reads != 4 {
					t.Fatal("fresh scoped identity unavailable", err)
				}
			} else if err == nil {
				t.Fatal("changed identity inherited signature proof", mode)
			}
		})
	}
}

func TestQualifiedChromeIdentityHonorsDeadlineDuringSecondIdentityPass(t *testing.T) {
	policy := ChromeProcessPolicy{ExpectedUID: 501, NativeHostExecutable: "/fixture/native", ChromeExecutable: "/fixture/Chrome", NativeHostRequirement: "exact native", ChromeRequirement: "exact Chrome"}
	host := session.ProcessIdentity{PID: 10, UID: 501, StartToken: "host", Executable: policy.NativeHostExecutable}
	chrome := session.ProcessIdentity{PID: 20, UID: 501, StartToken: "chrome", Executable: policy.ChromeExecutable}
	expected := ChromeProcessEvidence{KernelPeerQualified: true, NativeHost: host, ChromeParent: chrome, Ancestors: []session.ProcessIdentity{chrome}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reads := 0
	err := verifyQualifiedChromePeerIdentity(ctx, policy, expected, func() (int, error) { return 10, nil }, func(pid int) (processParent, error) {
		reads++
		if reads == 3 {
			cancel()
		}
		if pid == 10 {
			return processParent{identity: host, parentPID: 20}, nil
		}
		return processParent{identity: chrome, parentPID: 1}, nil
	})
	if !errors.Is(err, context.Canceled) || reads != 3 {
		t.Fatal("expired scoped probe completed second read pass")
	}
}
