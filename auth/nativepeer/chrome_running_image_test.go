package nativepeer

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestPinnedRunningChromeSurvivesCanonicalReplacementWithAllOriginalProofs(t *testing.T) {
	canonical, actual, o := chromeImageFixture(t)
	if e := os.Remove(canonical); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(canonical, []byte("new vendor release"), 0700); e != nil {
		t.Fatal(e)
	}
	policy, nodes := ancestryFixture()
	policy.ChromeExecutable = canonical
	policy.ChromeRequirement = o.DesignatedRequirement
	policy.ExpectedUID = o.ExpectedUID
	for id, node := range nodes {
		node.identity.UID = o.ExpectedUID
		nodes[id] = node
	}
	node := nodes[20]
	node.identity.Executable = actual
	nodes[20] = node
	static := []string{}
	dynamic := []string{}
	verify := func(pid int, requirement string) error {
		if pid == 20 {
			dynamic = append(dynamic, requirement)
		}
		return nil
	}
	result, e := verifyChromeProcess(context.Background(), 10, policy, func(pid int) (processParent, error) { return nodes[pid], nil }, verify, func(ancestor processParent) (func() error, error) {
		return verifyChromeAncestorImage(policy, ancestor, func(path string, options Options) error {
			if path != actual {
				t.Fatal("replacement was treated as enrolled image")
			}
			static = append(static, options.DesignatedRequirement)
			return nil
		}, verify)
	})
	if e != nil || result.ChromeParent != node.identity || result.KernelPeerQualified || result.ProfileQualified || result.ExecutorQualified {
		t.Fatal("running signed process proof failed or minted unrelated authority", e)
	}
	if len(static) != 2 || static[0] != GoogleChromeSignerRequirement || static[1] != policy.ChromeRequirement || len(dynamic) != 2 || dynamic[0] != GoogleChromeSignerRequirement || dynamic[1] != policy.ChromeRequirement {
		t.Fatal("original static/dynamic and independent vendor proof not all checked")
	}
}
func TestPinnedRunningChromeRejectsSignatureSubstitutionAndLateIdentityChanges(t *testing.T) {
	for _, mode := range []string{"staticVendor", "staticPin", "dynamicVendor", "dynamicPin", "fileChanged", "processBirth", "parentChain", "uid", "symlink", "worldWritable"} {
		t.Run(mode, func(t *testing.T) {
			canonical, actual, o := chromeImageFixture(t)
			os.Remove(canonical)
			if e := os.WriteFile(canonical, []byte("updated"), 0700); e != nil {
				t.Fatal(e)
			}
			if mode == "symlink" {
				os.Remove(actual)
				if e := os.Symlink(canonical, actual); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "worldWritable" {
				os.Chmod(actual, 0777)
			}
			policy, nodes := ancestryFixture()
			policy.ChromeExecutable = canonical
			policy.ChromeRequirement = o.DesignatedRequirement
			policy.ExpectedUID = o.ExpectedUID
			for id, node := range nodes {
				node.identity.UID = o.ExpectedUID
				nodes[id] = node
			}
			node := nodes[20]
			node.identity.Executable = actual
			if mode == "uid" {
				node.identity.UID++
			}
			nodes[20] = node
			checks := map[int]int{}
			verify := func(pid int, required string) error {
				if pid == 20 && (mode == "dynamicVendor" && required == GoogleChromeSignerRequirement || mode == "dynamicPin" && required == policy.ChromeRequirement) {
					return errors.New("fixture denied")
				}
				return nil
			}
			_, e := verifyChromeProcess(context.Background(), 10, policy, func(pid int) (processParent, error) {
				checks[pid]++
				node := nodes[pid]
				if pid == 20 && checks[pid] > 1 && mode == "processBirth" {
					node.identity.StartToken = "reused"
				}
				if pid == 10 && checks[pid] > 1 && mode == "parentChain" {
					node.parentPID = 30
				}
				return node, nil
			}, verify, func(ancestor processParent) (func() error, error) {
				return verifyChromeAncestorImage(policy, ancestor, func(_ string, options Options) error {
					if mode == "staticVendor" && options.DesignatedRequirement == GoogleChromeSignerRequirement || mode == "staticPin" && options.DesignatedRequirement == policy.ChromeRequirement {
						return errors.New("fixture denied")
					}
					if mode == "fileChanged" {
						os.Chmod(actual, 0600)
					}
					return nil
				}, verify)
			})
			if e == nil {
				t.Fatal("invalid running image proof accepted", mode)
			}
		})
	}
}
