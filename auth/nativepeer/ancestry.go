package nativepeer

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/viant/mechanize/session"
)

// ChromeProcessPolicy comes only from operator enrollment. Profile and renderer
// authority are separate: signed Chrome ancestry cannot prove a Chrome profile.
type ChromeProcessPolicy struct {
	ExpectedUID           uint32 `json:"expectedUID"`
	NativeHostExecutable  string `json:"nativeHostExecutable"`
	NativeHostRequirement string `json:"nativeHostRequirement"`
	ChromeExecutable      string `json:"chromeExecutable"`
	ChromeRequirement     string `json:"chromeRequirement"`
	MaximumAncestors      int    `json:"maximumAncestors,omitempty"`
}
type ChromeProcessEvidence struct {
	NativeHost          session.ProcessIdentity   `json:"nativeHost"`
	ChromeParent        session.ProcessIdentity   `json:"chromeParent"`
	Ancestors           []session.ProcessIdentity `json:"ancestors"`
	VerifiedAt          time.Time                 `json:"verifiedAt"`
	KernelPeerQualified bool                      `json:"kernelPeerQualified"`
	ProfileQualified    bool                      `json:"profileQualified"`
	ExecutorQualified   bool                      `json:"executorQualified"`
}
type ChromePeerVerifier struct {
	policy ChromeProcessPolicy
	peer   func(*net.UnixConn) error
}
type processParent struct {
	identity  session.ProcessIdentity
	parentPID int
}

func validateChromePolicy(policy ChromeProcessPolicy) error {
	if !filepath.IsAbs(policy.NativeHostExecutable) || !filepath.IsAbs(policy.ChromeExecutable) || policy.NativeHostExecutable == policy.ChromeExecutable || strings.TrimSpace(policy.NativeHostRequirement) == "" || strings.TrimSpace(policy.ChromeRequirement) == "" || strings.ContainsRune(policy.NativeHostRequirement, 0) || strings.ContainsRune(policy.ChromeRequirement, 0) || policy.MaximumAncestors < 0 || policy.MaximumAncestors > 16 {
		return errors.New("explicit distinct native-host/Chrome images, requirements and bounded ancestry required")
	}
	return nil
}
func NewChromePeerVerifier(policy ChromeProcessPolicy) (*ChromePeerVerifier, error) {
	if err := validateChromePolicy(policy); err != nil {
		return nil, err
	}
	peer, err := NewVerifier(Options{ExpectedUID: policy.ExpectedUID, DesignatedRequirement: policy.NativeHostRequirement})
	if err != nil {
		return nil, err
	}
	if err = VerifyExecutable(policy.NativeHostExecutable, Options{ExpectedUID: policy.ExpectedUID, DesignatedRequirement: policy.NativeHostRequirement}); err != nil {
		return nil, err
	}
	if err = VerifyExecutable(policy.ChromeExecutable, Options{ExpectedUID: policy.ExpectedUID, DesignatedRequirement: policy.ChromeRequirement}); err != nil {
		return nil, err
	}
	return &ChromePeerVerifier{policy: policy, peer: peer}, nil
}

// Verify authenticates the actual kernel Unix peer first. A hello PID, browser
// name, file path, credential or ancestry assertion is never accepted as proof.
func (v *ChromePeerVerifier) Verify(ctx context.Context, conn *net.UnixConn) (ChromeProcessEvidence, error) {
	if v == nil || v.peer == nil || ctx.Err() != nil {
		return ChromeProcessEvidence{}, errors.Join(ctx.Err(), errors.New("Chrome peer verifier unavailable"))
	}
	if err := v.peer(conn); err != nil {
		return ChromeProcessEvidence{}, err
	}
	pid, err := AuditPID(conn)
	if err != nil {
		return ChromeProcessEvidence{}, err
	}
	evidence, err := VerifyChromeProcess(ctx, pid, v.policy)
	if err != nil {
		return evidence, err
	}
	if err = v.peer(conn); err != nil {
		return ChromeProcessEvidence{}, err
	}
	current, err := AuditPID(conn)
	if err != nil || current != pid {
		return ChromeProcessEvidence{}, errors.Join(err, errors.New("native-host audit peer changed"))
	}
	evidence.KernelPeerQualified = true
	return evidence, ctx.Err()
}

// VerifyChromeProcess is also used by the signed native host on os.Getpid()
// before it loads credentials. It does not authenticate a socket peer. The
// broker always uses Verify above; untrusted messages cannot select its PID.
func VerifyChromeProcess(ctx context.Context, pid int, policy ChromeProcessPolicy) (ChromeProcessEvidence, error) {
	if err := validateChromePolicy(policy); err != nil {
		return ChromeProcessEvidence{}, err
	}
	return verifyChromeProcess(ctx, pid, policy, inspectProcessParent, verifyDynamicProcess)
}
func verifyChromeProcess(ctx context.Context, pid int, policy ChromeProcessPolicy, inspect func(int) (processParent, error), verify func(int, string) error) (ChromeProcessEvidence, error) {
	var evidence ChromeProcessEvidence
	if err := ctx.Err(); err != nil {
		return evidence, err
	}
	leaf, err := inspect(pid)
	if err != nil {
		return evidence, err
	}
	if leaf.identity.PID != pid || leaf.identity.UID != policy.ExpectedUID || leaf.identity.StartToken == "" || leaf.identity.Executable != policy.NativeHostExecutable {
		return evidence, errors.New("native-host process does not match enrolled image and UID")
	}
	if err = verify(pid, policy.NativeHostRequirement); err != nil {
		return evidence, err
	}
	evidence.NativeHost = leaf.identity
	nodes := []processParent{leaf}
	seen := map[int]bool{pid: true}
	limit := policy.MaximumAncestors
	if limit == 0 {
		limit = 8
	}
	next := leaf.parentPID
	found := false
	for depth := 0; depth < limit; depth++ {
		if err = ctx.Err(); err != nil {
			return ChromeProcessEvidence{}, err
		}
		if next <= 1 || seen[next] {
			return ChromeProcessEvidence{}, errors.New("enrolled Chrome ancestor unavailable")
		}
		seen[next] = true
		ancestor, e := inspect(next)
		if e != nil {
			return ChromeProcessEvidence{}, e
		}
		if ancestor.identity.PID != next || ancestor.identity.UID != policy.ExpectedUID || ancestor.identity.StartToken == "" {
			return ChromeProcessEvidence{}, errors.New("Chrome ancestry identity or UID mismatch")
		}
		nodes = append(nodes, ancestor)
		evidence.Ancestors = append(evidence.Ancestors, ancestor.identity)
		if ancestor.identity.Executable == policy.ChromeExecutable {
			if e = verify(next, policy.ChromeRequirement); e != nil {
				return ChromeProcessEvidence{}, e
			}
			evidence.ChromeParent = ancestor.identity
			found = true
			break
		}
		next = ancestor.parentPID
	}
	if !found {
		return ChromeProcessEvidence{}, errors.New("signed Chrome ancestor not found within enrolled bound")
	}
	// Public libproc identity/start and parent links must remain unchanged across
	// the Security dynamic code checks. A PID-only socket fallback never occurs.
	for _, node := range nodes {
		current, e := inspect(node.identity.PID)
		if e != nil || current != node {
			return ChromeProcessEvidence{}, errors.Join(e, errors.New("Chrome ancestry changed during verification"))
		}
	}
	if err = ctx.Err(); err != nil {
		return ChromeProcessEvidence{}, err
	}
	evidence.VerifiedAt = time.Now()
	// No profile or old-renderer quiescence proof exists in this layer.
	return evidence, nil
}
