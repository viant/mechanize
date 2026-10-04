package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
)

type chromeRetirementEvidencePrimitives struct {
	Inspect func(context.Context, int) (session.ProcessIdentity, bool, error)
	Verify  func(context.Context, string, nativepeer.Options) error
	Hash    func(context.Context, string) (string, error)
}

var errChromeRetirementEvidence = errors.New("verified exact Chrome retirement process and enrollment evidence required")
var retirementEvidenceHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var retirementEvidenceExtension = regexp.MustCompile(`^chrome-extension://([a-p]{32})/$`)

// newChromeRetirementEvidenceProvider is trusted host enrollment only. The broker
// requirement comes from operator configuration, never a retirement wire body.
func newChromeRetirementEvidenceProvider(brokerRequirement string, primitives chromeRetirementEvidencePrimitives) (retirementEvidenceProvider, error) {
	if !retirementRequirement(brokerRequirement) {
		return nil, errChromeRetirementEvidence
	}
	if primitives.Inspect == nil {
		primitives.Inspect = func(ctx context.Context, pid int) (session.ProcessIdentity, bool, error) {
			if e := ctx.Err(); e != nil {
				return session.ProcessIdentity{}, false, e
			}
			return session.InspectProcess(pid)
		}
	}
	if primitives.Verify == nil {
		primitives.Verify = func(ctx context.Context, path string, o nativepeer.Options) error {
			if e := ctx.Err(); e != nil {
				return e
			}
			e := nativepeer.VerifyExecutable(path, o)
			if e != nil {
				return e
			}
			return ctx.Err()
		}
	}
	if primitives.Hash == nil {
		primitives.Hash = stableRetirementExecutableSHA256
	}
	return func(ctx context.Context, s chrome.LifecycleReceiptInventory) (data.ChromeRetirementProcessEvidence, data.ChromeRetirementPolicyEvidence, error) {
		fail := func() (data.ChromeRetirementProcessEvidence, data.ChromeRetirementPolicyEvidence, error) {
			return data.ChromeRetirementProcessEvidence{}, data.ChromeRetirementPolicyEvidence{}, errChromeRetirementEvidence
		}
		p, e := auth.FromContext(ctx)
		if e != nil || !p.HasScope("desktop:control") || p.Namespace != s.Owner || p.ClientID == "" || p.ClientID != s.ClientID || s.GuardID == "" || s.ProcessTrust == nil || !s.Process.KernelPeerQualified || len(s.Process.Ancestors) != 1 || s.Process.Ancestors[0] != s.Process.ChromeParent {
			return fail()
		}
		trust := *s.ProcessTrust
		host, parent := s.Process.NativeHost, s.Process.ChromeParent
		if !retirementRequirement(trust.NativeHostRequirement) || !retirementRequirement(trust.ChromeRequirement) || host.PID <= 0 || parent.PID <= 0 || host.PID == parent.PID || host.UID != trust.ExpectedUID || parent.UID != trust.ExpectedUID || host.Executable != trust.NativeHostExecutable || parent.Executable != trust.ChromeExecutable || !model.ValidProcessStartToken(host.StartToken) || !model.ValidProcessStartToken(parent.StartToken) || !retirementExecutablePath(host.Executable) || !retirementExecutablePath(parent.Executable) {
			return fail()
		}
		extension := retirementEvidenceExtension.FindStringSubmatch(s.ExtensionOrigin)
		if len(extension) != 2 || len(s.Origins) == 0 {
			return fail()
		}
		origins := append([]string(nil), s.Origins...)
		sort.Strings(origins)
		for i, origin := range origins {
			if !exactRetirementOrigin(origin) || i > 0 && origin == origins[i-1] {
				return fail()
			}
		}
		policy := data.ChromeRetirementPolicyEvidence{Version: 1, ExtensionID: extension[1], TrustScope: s.TrustScope, OriginScopeDigest: data.ChromeRetirementDigest(origins), NativeHostRequirementDigest: retirementStringSHA256(trust.NativeHostRequirement), ChromeRequirementDigest: retirementStringSHA256(trust.ChromeRequirement), BrokerRequirementDigest: retirementStringSHA256(brokerRequirement), ProfileQualified: s.ProfileQualified}
		if s.TrustScope == chrome.TrustScopeProfile {
			if !s.ProfileQualified || !retirementExecutablePath(s.ProfileDirectory) {
				return fail()
			}
			policy.ProfileScopeDigest = retirementStringSHA256(s.ProfileDirectory)
		} else if s.TrustScope != chrome.TrustScopeDesktop || s.ProfileQualified || s.ProfileDirectory != "" {
			return fail()
		}
		bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		identities := []session.ProcessIdentity{host, parent}
		requirements := []string{trust.NativeHostRequirement, trust.ChromeRequirement}
		hashes := make([]string, 2)
		inspect := func(expected session.ProcessIdentity) bool {
			actual, alive, e := primitives.Inspect(bounded, expected.PID)
			return e == nil && alive && actual == expected && bounded.Err() == nil
		}
		for _, id := range identities {
			if !inspect(id) {
				return fail()
			}
		}
		for index, id := range identities {
			options := nativepeer.Options{ExpectedUID: trust.ExpectedUID, DesignatedRequirement: requirements[index]}
			if e := primitives.Verify(bounded, id.Executable, options); e != nil || bounded.Err() != nil {
				return fail()
			}
			digest, e := primitives.Hash(bounded, id.Executable)
			if e != nil || !retirementEvidenceHash.MatchString(digest) || bounded.Err() != nil {
				return fail()
			}
			if e = primitives.Verify(bounded, id.Executable, options); e != nil || !inspect(id) {
				return fail()
			}
			hashes[index] = digest
		}
		// Catch a native-host change while the Chrome image was being verified/hashed.
		for _, id := range identities {
			if !inspect(id) {
				return fail()
			}
		}
		process := data.ChromeRetirementProcessEvidence{Version: 1, NativeHostPID: host.PID, NativeHostUID: host.UID, NativeHostBirth: host.StartToken, NativeHostImageDigest: hashes[0], ChromePID: parent.PID, ChromeUID: parent.UID, ChromeBirth: parent.StartToken, ChromeImageDigest: hashes[1], KernelPeerQualified: true, ImmediateParentQualified: true}
		return process, policy, nil
	}, nil
}
func retirementRequirement(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= 16384 && !strings.ContainsRune(value, 0)
}
func retirementExecutablePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path, 0)
}
func retirementStringSHA256(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func exactRetirementOrigin(origin string) bool {
	parsed, e := url.Parse(origin)
	return e == nil && parsed.User == nil && parsed.Host != "" && parsed.Scheme+"://"+parsed.Host == origin && (parsed.Scheme == "https" || parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1")) && !strings.ContainsAny(origin, "*\\")
}

// Hash only an unchanged regular executable descriptor. Signature verification
// surrounds this primitive; no requested or configured digest is substituted.
func stableRetirementExecutableSHA256(ctx context.Context, path string) (string, error) {
	if !retirementExecutablePath(path) {
		return "", errChromeRetirementEvidence
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil || resolved != path {
		return "", errChromeRetirementEvidence
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return "", errChromeRetirementEvidence
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	before, e := file.Stat()
	if e != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 || before.Mode().Perm()&0111 == 0 || before.Size() <= 0 || before.Size() > 512<<20 {
		return "", errChromeRetirementEvidence
	}
	hash := sha256.New()
	buffer := make([]byte, 128<<10)
	var total int64
	for {
		if e = ctx.Err(); e != nil {
			return "", e
		}
		n, readErr := file.Read(buffer)
		if n > 0 {
			total += int64(n)
			if total > 512<<20 {
				return "", errChromeRetirementEvidence
			}
			_, _ = hash.Write(buffer[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", errChromeRetirementEvidence
		}
	}
	after, e := file.Stat()
	if e != nil {
		return "", errChromeRetirementEvidence
	}
	current, e := os.Lstat(path)
	if e != nil || !os.SameFile(before, after) || !os.SameFile(before, current) || before.Size() != after.Size() || before.Size() != current.Size() || !before.ModTime().Equal(after.ModTime()) || !before.ModTime().Equal(current.ModTime()) {
		return "", errChromeRetirementEvidence
	}
	resolved, e = filepath.EvalSymlinks(path)
	if e != nil || resolved != path || ctx.Err() != nil {
		return "", errChromeRetirementEvidence
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
