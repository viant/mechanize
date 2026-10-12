package nativepeer

import (
	"context"
	"errors"
	"net"

	"github.com/viant/mechanize/session"
)

// VerifyQualifiedChromePeerIdentity rechecks kernel/process identity for an
// already fully qualified, private operation. It is not signature qualification
// and must never admit a channel or replace full trust checks at actual input.
func VerifyQualifiedChromePeerIdentity(ctx context.Context, conn *net.UnixConn, policy ChromeProcessPolicy, expected ChromeProcessEvidence) error {
	if conn == nil {
		return errors.New("qualified Chrome socket unavailable")
	}
	return verifyQualifiedChromePeerIdentity(ctx, policy, expected, func() (int, error) { return AuditPID(conn) }, inspectProcessParent)
}

func verifyQualifiedChromePeerIdentity(ctx context.Context, policy ChromeProcessPolicy, expected ChromeProcessEvidence, audit func() (int, error), inspect func(int) (processParent, error)) error {
	denied := errors.New("qualified Chrome peer identity changed")
	if validateChromePolicy(policy) != nil || !expected.KernelPeerQualified || audit == nil || inspect == nil || expected.NativeHost.Executable != policy.NativeHostExecutable || len(expected.Ancestors) == 0 {
		return denied
	}
	limit := policy.MaximumAncestors
	if limit == 0 {
		limit = 8
	}
	if len(expected.Ancestors) > limit || expected.Ancestors[len(expected.Ancestors)-1] != expected.ChromeParent {
		return denied
	}
	identities := append([]session.ProcessIdentity{expected.NativeHost}, expected.Ancestors...)
	seen := map[int]bool{}
	for _, id := range identities {
		if id.PID <= 1 || id.UID != policy.ExpectedUID || id.StartToken == "" || id.Executable == "" || seen[id.PID] {
			return denied
		}
		seen[id.PID] = true
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	pid, err := audit()
	if err != nil || pid != expected.NativeHost.PID {
		return denied
	}
	snapshots := make([]processParent, len(identities))
	for i, id := range identities {
		if err := ctx.Err(); err != nil {
			return err
		}
		actual, e := inspect(id.PID)
		if e != nil || actual.identity != id || i+1 < len(identities) && actual.parentPID != identities[i+1].PID {
			return denied
		}
		snapshots[i] = actual
	}
	// Repeat the identity/link reads across the entire probe, just as full trust
	// qualification does. PID reuse or reparenting never inherits the old proof.
	for i, id := range identities {
		if err := ctx.Err(); err != nil {
			return err
		}
		actual, e := inspect(id.PID)
		if e != nil || actual != snapshots[i] {
			return denied
		}
	}
	current, err := audit()
	if err != nil || current != pid {
		return denied
	}
	return ctx.Err()
}
