package nativepeer

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func chromeImageFixture(t *testing.T) (string, string, Options) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	canonical := filepath.Join(dir, "enrolled-main")
	actual := filepath.Join(dir, "arbitrary-kernel-path")
	if err = os.WriteFile(canonical, []byte("fixture image"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(canonical, actual); err != nil {
		t.Fatal(err)
	}
	return canonical, actual, Options{ExpectedUID: uint32(os.Getuid()), DesignatedRequirement: "fixture requirement"}
}
func TestChromeHardlinkIdentityChecksCanonicalSignatureAndKeepsNativeStrict(t *testing.T) {
	canonical, actual, options := chromeImageFixture(t)
	seen := []string{}
	recheck, err := verifyChromeImage(canonical, actual, options, func(path string, o Options) error {
		seen = append(seen, path)
		if o != options {
			t.Fatal("requirement changed")
		}
		return nil
	})
	if err != nil || recheck == nil || len(seen) != 1 {
		t.Fatal("hardlink not qualified", err, seen)
	}
	if recheck() != nil || seen[0] != canonical {
		t.Fatal("hardlink not qualified", err, seen)
	}
	if VerifyExecutable(canonical, options) == nil || VerifyExecutable(actual, options) == nil {
		t.Fatal("ordinary/native executable accepted hardlinks")
	}
	if err = os.Remove(actual); err != nil {
		t.Fatal(err)
	}
	if recheck() == nil {
		t.Fatal("changed physical linkage accepted")
	}
}
func TestChromeImageRejectsCopiesSymlinksOtherInodesAndReplacements(t *testing.T) {
	for _, kind := range []string{"copy", "symlink", "other-hardlink", "replace-canonical", "replace-running", "mode-change"} {
		t.Run(kind, func(t *testing.T) {
			canonical, actual, o := chromeImageFixture(t)
			replace := func(path string) {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("fixture image"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "copy":
				replace(actual)
			case "symlink":
				os.Remove(actual)
				if err := os.Symlink(canonical, actual); err != nil {
					t.Fatal(err)
				}
			case "other-hardlink":
				other := filepath.Join(filepath.Dir(actual), "other")
				os.WriteFile(other, []byte("fixture image"), 0700)
				os.Remove(actual)
				if err := os.Link(other, actual); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			_, err := verifyChromeImage(canonical, actual, o, func(string, Options) error {
				calls++
				if calls == 1 {
					switch kind {
					case "replace-canonical":
						replace(canonical)
					case "replace-running":
						replace(actual)
					case "mode-change":
						os.Chmod(actual, 0722)
					}
				}
				return nil
			})
			if err == nil {
				t.Fatal("substituted Chrome image accepted")
			}
		})
	}
}
func TestChromeAncestryHardlinkRetainsKernelImageAndRejectsLateReplacement(t *testing.T) {
	for _, replaceLate := range []bool{false, true} {
		t.Run(map[bool]string{false: "actualPath", true: "lateReplacement"}[replaceLate], func(t *testing.T) {
			canonical, actual, o := chromeImageFixture(t)
			policy, nodes := ancestryFixture()
			policy.ExpectedUID = o.ExpectedUID
			policy.ChromeExecutable = canonical
			for id, node := range nodes {
				node.identity.UID = o.ExpectedUID
				nodes[id] = node
			}
			node := nodes[20]
			node.identity.Executable = actual
			nodes[20] = node
			checks := 0
			result, err := verifyChromeProcess(context.Background(), 10, policy, func(pid int) (processParent, error) {
				checks++
				if replaceLate && checks == 4 {
					os.Remove(canonical)
					os.WriteFile(canonical, []byte("replacement"), 0700)
				}
				return nodes[pid], nil
			}, func(int, string) error { return nil }, func(path string) (func() error, error) {
				return verifyChromeImage(canonical, path, o, func(string, Options) error { return nil })
			})
			if replaceLate {
				if err == nil {
					t.Fatal("replacement during process recheck accepted")
				}
				return
			}
			if err != nil || result.ChromeParent.Executable != actual || result.Ancestors[0].Executable != actual {
				t.Fatal("actual kernel image rewritten or rejected", err)
			}
		})
	}
}

func TestChromeGroupWriteRequiresMacOSAdminAndNeverWorldWrite(t *testing.T) {
	lookup := func(name string) (*user.Group, error) {
		if name != "admin" {
			t.Fatal("unexpected group lookup")
		}
		return &user.Group{Name: "admin", Gid: "80"}, nil
	}
	for _, tc := range []struct {
		mode     os.FileMode
		gid      uint32
		platform string
		want     bool
	}{{0755, 20, "darwin", true}, {0775, 80, "darwin", true}, {0775, 20, "darwin", false}, {0775, 0, "darwin", false}, {0777, 80, "darwin", false}, {0775, 80, "linux", false}, {os.ModeSetuid | 0755, 80, "darwin", false}} {
		if chromeImageMode(tc.mode, tc.gid, tc.platform, lookup) != tc.want {
			t.Fatal("unsafe Chrome mode decision", tc)
		}
	}
	if chromeImageMode(0775, 80, "darwin", func(string) (*user.Group, error) { return nil, os.ErrNotExist }) {
		t.Fatal("missing admin group accepted")
	}
}
