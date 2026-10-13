package nativepeer

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// GoogleChromeSignerRequirement is the closed Google Chrome publisher identity.
// Enrollment may choose this exact policy to follow signed Chrome updates, or
// retain a build-specific requirement. Other publisher expressions are not an
// implicit update policy.
const GoogleChromeSignerRequirement = `identifier "com.google.Chrome" and anchor apple generic and certificate leaf[subject.OU] = "EQHXZ8M8AV"`

// VerifyChromeExecutable is exclusively for the enrolled canonical Chrome main
// image. Chromium hardlinks that main image into its signed launch clone. Other
// executables continue to require VerifyExecutable's single-link invariant.
func VerifyChromeExecutable(path string, options Options) error {
	_, err := verifyChromeImage(path, path, options, verifyExecutable)
	return err
}

type chromeImageIdentity struct {
	device, inode, links uint64
	owner, group         uint32
	mode                 os.FileMode
	size                 int64
	modified             int64
}

func chromeImageStat(path string, options Options) (chromeImageIdentity, error) {
	fail := errors.New("Chrome executable identity unavailable")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.TrimSpace(options.DesignatedRequirement) == "" || strings.ContainsRune(options.DesignatedRequirement, 0) {
		return chromeImageIdentity{}, fail
	}
	info, err := os.Lstat(path)
	if err != nil {
		return chromeImageIdentity{}, fail
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || !chromeImageMode(info.Mode(), stat.Gid, runtime.GOOS, user.LookupGroup) || info.Mode().Perm()&0111 == 0 || (stat.Uid != options.ExpectedUID && stat.Uid != 0) || stat.Nlink < 1 {
		return chromeImageIdentity{}, fail
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return chromeImageIdentity{}, fail
	}
	return chromeImageIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino), links: uint64(stat.Nlink), owner: stat.Uid, group: stat.Gid, mode: info.Mode(), size: info.Size(), modified: info.ModTime().UnixNano()}, nil
}

// Group-write is accepted only for the privileged macOS admin group. The caller
// must additionally verify the independent Google signer below. Other groups,
// world-write and special permission bits are never accepted.
func chromeImageMode(mode os.FileMode, gid uint32, platform string, lookup func(string) (*user.Group, error)) bool {
	if mode.Perm()&0002 != 0 || mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	if mode.Perm()&0020 == 0 {
		return true
	}
	if platform != "darwin" || lookup == nil {
		return false
	}
	group, err := lookup("admin")
	if err != nil || group == nil || group.Name != "admin" {
		return false
	}
	id, err := strconv.ParseUint(group.Gid, 10, 32)
	return err == nil && uint32(id) == gid
}

// verifyChromeImage pins both path identities across canonical static signing.
// Clone bundle metadata is not the enrolled bundle: strict clone-resource
// validation is deliberately not substituted for the canonical signed image.
// The returned recheck must bracket exact dynamic process/ancestry inspection.
// No path name, byte equality or clone-directory convention grants authority.
func verifyChromeImage(canonical, actual string, options Options, signature func(string, Options) error) (func() error, error) {
	fail := errors.New("Chrome running image does not match enrolled image")
	enrolled, err := chromeImageStat(canonical, options)
	if err != nil {
		return nil, err
	}
	running, err := chromeImageStat(actual, options)
	if err != nil {
		return nil, err
	}
	if enrolled != running {
		return nil, fail
	}
	recheck := func() error {
		a, e := chromeImageStat(canonical, options)
		if e != nil || a != enrolled {
			return fail
		}
		b, e := chromeImageStat(actual, options)
		if e != nil || b != running || a != b {
			return fail
		}
		return nil
	}
	if signature == nil {
		return nil, fail
	}
	if enrolled.mode.Perm()&0020 != 0 {
		google := options
		google.DesignatedRequirement = GoogleChromeSignerRequirement
		if err = signature(canonical, google); err != nil {
			return nil, err
		}
		if err = recheck(); err != nil {
			return nil, err
		}
	}
	if err = signature(canonical, options); err != nil {
		return nil, err
	}
	if err = recheck(); err != nil {
		return nil, err
	}
	return recheck, nil
}

// The argument is an ancestor already obtained from the kernel and checked for
// PID, UID and birth by verifyChromeProcess. An update may replace the canonical
// file while Chrome keeps its old signed launch image. In that case only the
// enrolled code requirement plus independent Google identity can qualify that
// running image. The explicit follow-updates policy additionally anchors the
// current canonical installation; an exact hash policy remains exact. Neither a path nor matching bytes grants trust.
func verifyChromeAncestorImage(policy ChromeProcessPolicy, ancestor processParent, signature func(string, Options) error, dynamic func(int, string) error) (func() error, error) {
	options := Options{ExpectedUID: policy.ExpectedUID, DesignatedRequirement: policy.ChromeRequirement}
	if proof, err := verifyChromeImage(policy.ChromeExecutable, ancestor.identity.Executable, options, signature); err == nil {
		return proof, nil
	}
	var canonicalProof func() error
	if policy.ChromeRequirement == GoogleChromeSignerRequirement {
		// Following releases does not remove the enrolled installation anchor.
		// The current canonical image and the older running image must each
		// independently satisfy Google identity and remain stable throughout.
		var err error
		canonicalProof, err = verifyChromeImage(policy.ChromeExecutable, policy.ChromeExecutable, options, signature)
		if err != nil {
			return nil, err
		}
	}
	proof, err := verifyPinnedRunningChromeImage(ancestor.identity.Executable, options, signature)
	if err != nil {
		return nil, err
	}
	if dynamic == nil {
		return nil, errors.New("running Chrome vendor proof unavailable")
	}
	if err = dynamic(ancestor.identity.PID, GoogleChromeSignerRequirement); err != nil {
		return nil, err
	}
	if err = proof(); err != nil {
		return nil, err
	}
	// The caller next verifies this same PID against ChromeRequirement and
	// brackets both dynamic checks with unchanged kernel ancestry and this proof.
	if canonicalProof != nil {
		if err := canonicalProof(); err != nil {
			return nil, err
		}
		return func() error {
			if err := canonicalProof(); err != nil {
				return err
			}
			return proof()
		}, nil
	}
	return proof, nil
}
func verifyPinnedRunningChromeImage(actual string, options Options, signature func(string, Options) error) (func() error, error) {
	before, err := chromeImageStat(actual, options)
	if err != nil {
		return nil, err
	}
	recheck := func() error {
		after, e := chromeImageStat(actual, options)
		if e != nil || after != before {
			return errors.New("running Chrome image changed during verification")
		}
		return nil
	}
	if signature == nil {
		return nil, errors.New("running Chrome signature unavailable")
	}
	vendor := options
	vendor.DesignatedRequirement = GoogleChromeSignerRequirement
	for _, required := range []Options{vendor, options} {
		if err = signature(actual, required); err != nil {
			return nil, err
		}
		if err = recheck(); err != nil {
			return nil, err
		}
	}
	return recheck, nil
}
