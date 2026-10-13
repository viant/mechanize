package nativepeer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestChromeFollowUpdatesAcceptsNewReleaseAndPriorRunningImage(t *testing.T) {
	canonical, running, o := chromeImageFixture(t)
	policy, nodes := ancestryFixture()
	policy.ExpectedUID = o.ExpectedUID
	policy.ChromeExecutable = canonical
	policy.ChromeRequirement = GoogleChromeSignerRequirement
	for id, node := range nodes {
		node.identity.UID = o.ExpectedUID
		nodes[id] = node
	}
	node := nodes[20]
	node.identity.Executable = running
	nodes[20] = node
	static := func(path string, options Options) error {
		if options.DesignatedRequirement != GoogleChromeSignerRequirement {
			t.Fatal("update substituted non-Google trust")
		}
		return nil
	}
	dynamic := func(pid int, requirement string) error {
		if pid == 20 && requirement != GoogleChromeSignerRequirement {
			t.Fatal("running image lost publisher requirement")
		}
		return nil
	}
	prove := func() {
		t.Helper()
		evidence, e := verifyChromeProcess(context.Background(), 10, policy, func(pid int) (processParent, error) { return nodes[pid], nil }, dynamic, func(ancestor processParent) (func() error, error) {
			return verifyChromeAncestorImage(policy, ancestor, static, dynamic)
		})
		if e != nil || evidence.ChromeParent != nodes[20].identity || evidence.ProfileQualified || evidence.ExecutorQualified {
			t.Fatal("signed update proof failed or granted unrelated authority", e)
		}
	}
	prove()
	for _, release := range []string{"release-two", "release-three"} {
		if e := os.Remove(canonical); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(canonical, []byte(release), 0700); e != nil {
			t.Fatal(e)
		}
		prove() // The prior signed process continues across canonical replacement.
		next := filepath.Join(filepath.Dir(canonical), release+"-running")
		if e := os.Link(canonical, next); e != nil {
			t.Fatal(e)
		}
		node := nodes[20]
		node.identity.Executable = next
		node.identity.StartToken = release
		nodes[20] = node
		prove() // A relaunched current release needs no new hash/configuration.
	}
	if policy.ChromeRequirement != GoogleChromeSignerRequirement {
		t.Fatal("policy was rewritten")
	}
}

func TestChromeFollowUpdatesRequiresCurrentCanonicalAndRunningVendorProofs(t *testing.T) {
	for _, mode := range []string{"canonicalMissing", "canonicalVendor", "runningVendor", "dynamicVendor", "canonicalChange", "birthChange", "foreignUID", "runningSymlink", "runningWorldWrite"} {
		t.Run(mode, func(t *testing.T) {
			canonical, running, o := chromeImageFixture(t)
			os.Remove(canonical)
			if e := os.WriteFile(canonical, []byte("new release"), 0700); e != nil {
				t.Fatal(e)
			}
			policy, nodes := ancestryFixture()
			policy.ExpectedUID = o.ExpectedUID
			policy.ChromeExecutable = canonical
			policy.ChromeRequirement = GoogleChromeSignerRequirement
			for id, node := range nodes {
				node.identity.UID = o.ExpectedUID
				nodes[id] = node
			}
			node := nodes[20]
			node.identity.Executable = running
			if mode == "foreignUID" {
				node.identity.UID++
			}
			nodes[20] = node
			if mode == "canonicalMissing" {
				os.Remove(canonical)
			}
			if mode == "runningSymlink" {
				os.Remove(running)
				if e := os.Symlink(canonical, running); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "runningWorldWrite" {
				os.Chmod(running, 0777)
			}
			static := func(path string, _ Options) error {
				if mode == "canonicalVendor" && path == canonical || mode == "runningVendor" && path == running {
					return errors.New("fixture publisher refusal")
				}
				return nil
			}
			checks := 0
			dynamic := func(pid int, _ string) error {
				if pid == 20 {
					if mode == "dynamicVendor" {
						return errors.New("fixture running publisher refusal")
					}
					if mode == "canonicalChange" {
						os.Chmod(canonical, 0600)
					}
				}
				return nil
			}
			_, e := verifyChromeProcess(context.Background(), 10, policy, func(pid int) (processParent, error) {
				node := nodes[pid]
				if pid == 20 {
					checks++
					if checks > 1 && mode == "birthChange" {
						node.identity.StartToken = "reused"
					}
				}
				return node, nil
			}, dynamic, func(ancestor processParent) (func() error, error) {
				return verifyChromeAncestorImage(policy, ancestor, static, dynamic)
			})
			if e == nil {
				t.Fatal("unqualified update accepted", mode)
			}
		})
	}
}
