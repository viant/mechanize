package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/session"
)

func evidenceFixture(t *testing.T) (context.Context, chrome.LifecycleReceiptInventory, chromeRetirementEvidencePrimitives) {
	t.Helper()
	p, _ := auth.NewPrincipal("fixture", "", "retirement", []string{"desktop:control"})
	p.ClientID = "client"
	ctx := auth.WithPrincipal(context.Background(), p)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hostPath, chromePath := filepath.Join(dir, "host"), filepath.Join(dir, "chrome")
	if e := os.WriteFile(hostPath, []byte("host image"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(chromePath, []byte("chrome image"), 0700); e != nil {
		t.Fatal(e)
	}
	uid := uint32(os.Getuid())
	host := session.ProcessIdentity{PID: 111, UID: uid, StartToken: "100:1", Executable: hostPath}
	parent := session.ProcessIdentity{PID: 222, UID: uid, StartToken: "200:1", Executable: chromePath}
	snapshot := chrome.LifecycleReceiptInventory{Owner: p.Namespace, ClientID: p.ClientID, GuardID: "guard", TrustScope: chrome.TrustScopeDesktop, ExtensionOrigin: "chrome-extension://" + strings.Repeat("a", 32) + "/", Origins: []string{"https://two.test", "https://one.test"}, Process: nativepeer.ChromeProcessEvidence{NativeHost: host, ChromeParent: parent, Ancestors: []session.ProcessIdentity{parent}, KernelPeerQualified: true}, ProcessTrust: &nativepeer.ChromeProcessPolicy{ExpectedUID: uid, NativeHostExecutable: hostPath, NativeHostRequirement: "host designated pin", ChromeExecutable: chromePath, ChromeRequirement: "chrome designated pin"}}
	primitives := chromeRetirementEvidencePrimitives{Inspect: func(_ context.Context, pid int) (session.ProcessIdentity, bool, error) {
		if pid == host.PID {
			return host, true, nil
		}
		if pid == parent.PID {
			return parent, true, nil
		}
		return session.ProcessIdentity{}, false, nil
	}, Verify: func(_ context.Context, path string, o nativepeer.Options) error {
		expected := snapshot.ProcessTrust.NativeHostRequirement
		if path == chromePath {
			expected = snapshot.ProcessTrust.ChromeRequirement
		}
		if o.ExpectedUID != uid || o.DesignatedRequirement != expected {
			return errors.New("wrong verified requirement")
		}
		return nil
	}}
	return ctx, snapshot, primitives
}
func TestChromeRetirementEvidenceHashesVerifiedActualImagesAndExactPolicies(t *testing.T) {
	ctx, s, primitives := evidenceFixture(t)
	calls := 0
	verify := primitives.Verify
	primitives.Verify = func(c context.Context, p string, o nativepeer.Options) error { calls++; return verify(c, p, o) }
	provider, e := newChromeRetirementEvidenceProvider("broker exact designated requirement", primitives)
	if e != nil {
		t.Fatal(e)
	}
	process, policy, e := provider(ctx, s)
	if e != nil {
		t.Fatal(e)
	}
	if calls != 4 || process.NativeHostImageDigest != retirementStringSHA256("host image") || process.ChromeImageDigest != retirementStringSHA256("chrome image") || !process.KernelPeerQualified || !process.ImmediateParentQualified || policy.BrokerRequirementDigest != retirementStringSHA256("broker exact designated requirement") || policy.NativeHostRequirementDigest != retirementStringSHA256(s.ProcessTrust.NativeHostRequirement) || policy.ProfileQualified || policy.ProfileScopeDigest != "" {
		t.Fatal("fabricated/incorrect retirement evidence", process, policy, calls)
	}
	s.Origins[0], s.Origins[1] = s.Origins[1], s.Origins[0]
	_, reordered, e := provider(ctx, s)
	if e != nil || policy.OriginScopeDigest != reordered.OriginScopeDigest {
		t.Fatal("origin set hashing nondeterministic", e)
	}
	s.TrustScope = chrome.TrustScopeProfile
	s.ProfileQualified = true
	s.ProfileDirectory = filepath.Dir(s.Process.NativeHost.Executable)
	_, profile, e := provider(ctx, s)
	if e != nil || !profile.ProfileQualified || profile.ProfileScopeDigest != retirementStringSHA256(s.ProfileDirectory) {
		t.Fatal("profile scope proof incorrect", profile, e)
	}
}
func TestChromeRetirementEvidenceRejectsChangedProcessOrSignature(t *testing.T) {
	for _, mode := range []string{"dead", "PID", "birth", "UID", "path", "signature", "postSignature", "hash", "hashShape", "hostChangesWhileChromeHashes", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, s, primitives := evidenceFixture(t)
			inspect := primitives.Inspect
			counts := map[int]int{}
			changedHost := false
			primitives.Inspect = func(c context.Context, pid int) (session.ProcessIdentity, bool, error) {
				id, alive, e := inspect(c, pid)
				counts[pid]++
				if changedHost && pid == s.Process.NativeHost.PID {
					id.StartToken = "100:2"
				}
				if counts[pid] > 1 {
					switch mode {
					case "dead":
						alive = false
					case "PID":
						id.PID++
					case "birth":
						id.StartToken = "999:1"
					case "UID":
						id.UID++
					case "path":
						id.Executable += ".changed"
					}
				}
				return id, alive, e
			}
			verifyCalls := 0
			verify := primitives.Verify
			primitives.Verify = func(c context.Context, path string, o nativepeer.Options) error {
				verifyCalls++
				if mode == "signature" || mode == "postSignature" && verifyCalls == 2 {
					return errors.New("PRIVATE_CONFIG_OR_PATH")
				}
				return verify(c, path, o)
			}
			primitives.Hash = func(c context.Context, path string) (string, error) {
				if mode == "hash" {
					return "", errors.New("PRIVATE_VALUE")
				}
				if mode == "hashShape" {
					return "fabricated invalid digest", nil
				}
				digest, e := stableRetirementExecutableSHA256(c, path)
				if mode == "hostChangesWhileChromeHashes" && path == s.Process.ChromeParent.Executable {
					changedHost = true
				}
				return digest, e
			}
			if mode == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			provider, e := newChromeRetirementEvidenceProvider("broker pin", primitives)
			if e != nil {
				t.Fatal(e)
			}
			process, policy, e := provider(ctx, s)
			if e == nil || process.NativeHostImageDigest != "" || policy.BrokerRequirementDigest != "" || strings.Contains(e.Error(), "PRIVATE") {
				t.Fatal("unverified/secret evidence returned", process, policy, e)
			}
		})
	}
}
func TestChromeRetirementEvidenceRejectsScopeAndMissingEnrollment(t *testing.T) {
	for _, mode := range []string{"noActor", "foreignClient", "foreignOwner", "missingPolicy", "missingPin", "wrongEnrolledPath", "wrongEnrolledUID", "noKernelPeer", "wrongParent", "missingBrokerPin", "desktopClaimsProfile", "profileUnqualified", "invalidOrigin", "invalidExtension"} {
		t.Run(mode, func(t *testing.T) {
			ctx, s, primitives := evidenceFixture(t)
			broker := "broker pin"
			switch mode {
			case "noActor":
				ctx = context.Background()
			case "foreignClient":
				s.ClientID = "foreign"
			case "foreignOwner":
				s.Owner = strings.Repeat("b", 64)
			case "missingPolicy":
				s.ProcessTrust = nil
			case "missingPin":
				s.ProcessTrust.ChromeRequirement = ""
			case "wrongEnrolledPath":
				s.ProcessTrust.ChromeExecutable += ".other"
			case "wrongEnrolledUID":
				s.ProcessTrust.ExpectedUID++
			case "noKernelPeer":
				s.Process.KernelPeerQualified = false
			case "wrongParent":
				s.Process.Ancestors[0].PID++
			case "missingBrokerPin":
				broker = ""
			case "desktopClaimsProfile":
				s.ProfileQualified = true
			case "profileUnqualified":
				s.TrustScope = chrome.TrustScopeProfile
				s.ProfileDirectory = t.TempDir()
			case "invalidOrigin":
				s.Origins = []string{"https://private.test/path"}
			case "invalidExtension":
				s.ExtensionOrigin = "https://foreign.test"
			}
			provider, e := newChromeRetirementEvidenceProvider(broker, primitives)
			if e == nil {
				process, policy, err := provider(ctx, s)
				if err == nil || process.ChromeImageDigest != "" || policy.ChromeRequirementDigest != "" {
					t.Fatal("untrusted enrollment accepted", process, policy, err)
				}
			}
		})
	}
}
func TestStableRetirementExecutableHashRejectsUnsafeFilesAndCancellation(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "image")
	if e := os.WriteFile(path, []byte("exact actual bytes"), 0700); e != nil {
		t.Fatal(e)
	}
	digest, e := stableRetirementExecutableSHA256(context.Background(), path)
	if e != nil || digest != retirementStringSHA256("exact actual bytes") {
		t.Fatal("actual byte hash mismatch", digest, e)
	}
	link := filepath.Join(dir, "link")
	os.Symlink(path, link)
	if _, e = stableRetirementExecutableSHA256(context.Background(), link); e == nil {
		t.Fatal("symlink image accepted")
	}
	os.Chmod(path, 0777)
	if _, e = stableRetirementExecutableSHA256(context.Background(), path); e == nil {
		t.Fatal("shared writable image accepted")
	}
	os.Chmod(path, 0700)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = stableRetirementExecutableSHA256(ctx, path); e == nil {
		t.Fatal("canceled hash accepted")
	}
}
