package session

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/viant/mechanize/auth"
)

// ReconcileUnused clears only a stopped generation with authoritative proof that
// no durable dispatch intent existed. A callback must query the existing ledger;
// missing storage or any attempt is not proof. No input is posted or replayed.
func (s *Supervisor) ReconcileUnused(ctx context.Context, p auth.Principal, generation uint64, proveUnused func(context.Context, auth.Principal, uint64) error) (CleanupReport, error) {
	if err := actor(ctx, p); err != nil {
		return CleanupReport{}, err
	}
	if proveUnused == nil {
		return CleanupReport{}, ErrCleanupUnknown
	}
	return s.reconcileStopped(ctx, p, generation, "Existing durable ledger proves no dispatch intent for this stopped generation", false, func(ctx context.Context, lease Lease, helper ProcessIdentity) error {
		return proveUnused(ctx, p, lease.Generation)
	})
}

// ReconcileNeverDispatched releases only a stopped generation after a complete
// authoritative original-outcome check proves every attempt was rejected before
// dispatch. Absent effects from later business reconciliation are not proof.
func (s *Supervisor) ReconcileNeverDispatched(ctx context.Context, p auth.Principal, generation uint64, proveNeverDispatched func(context.Context, auth.Principal, uint64) error) (CleanupReport, error) {
	if err := actor(ctx, p); err != nil {
		return CleanupReport{}, err
	}
	if proveNeverDispatched == nil {
		return CleanupReport{}, ErrCleanupUnknown
	}
	return s.reconcileStopped(ctx, p, generation, "Original committed outcomes prove every attempt rejected before dispatch", false, func(ctx context.Context, lease Lease, helper ProcessIdentity) error {
		return proveNeverDispatched(ctx, p, lease.Generation)
	})
}

// ReconcileNoRawInput reconciles physical input only, without resolving or
// replaying uncertain application effects. It requires the historical profile
// persisted with the exact enrolled helper before dispatch. Legacy records have
// no such evidence and fail closed; current configuration cannot migrate them.
func (s *Supervisor) ReconcileNoRawInput(ctx context.Context, p auth.Principal, generation uint64) (CleanupReport, error) {
	return s.reconcileStopped(ctx, p, generation, "Persisted enrolled helper profile excluded raw input; application effects remain unresolved", true, nil)
}

func (s *Supervisor) reconcileStopped(ctx context.Context, p auth.Principal, generation uint64, reason string, businessUnknown bool, proof func(context.Context, Lease, ProcessIdentity) error) (CleanupReport, error) {
	if err := actor(ctx, p); err != nil {
		return CleanupReport{}, err
	}
	if generation == 0 {
		return CleanupReport{}, ErrCleanupUnknown
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		return CleanupReport{}, ErrContended
	}
	parent, err := os.Lstat(filepath.Dir(s.options.LockPath))
	if err != nil {
		return CleanupReport{}, err
	}
	owner, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0077 != 0 || owner.Uid != uint32(os.Getuid()) {
		return CleanupReport{}, ErrCleanupUnknown
	}
	fd, err := syscall.Open(s.options.LockPath, syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return CleanupReport{}, err
	}
	file := os.NewFile(uintptr(fd), s.options.LockPath)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return CleanupReport{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		return CleanupReport{}, ErrCleanupUnknown
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return CleanupReport{}, ErrContended
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	raw, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(raw) > 65536 {
		return CleanupReport{}, ErrCleanupUnknown
	}
	var prior record
	if json.Unmarshal(raw, &prior) != nil || prior.Generation != generation || prior.Lease == nil || prior.Lease.Generation != generation || prior.Lease.Owner != p.Namespace || prior.Lease.ID == "" || prior.Lease.Scope.Validate() != nil || prior.Helper == nil || prior.Helper.PID <= 0 || prior.Helper.StartToken == "" || prior.Helper.UID != uint32(os.Getuid()) || filepath.Clean(prior.Helper.Executable) != filepath.Clean(s.options.HelperExecutable) || prior.LastCleanup == nil || !prior.LastCleanup.UnknownInputs {
		return CleanupReport{}, ErrCleanupUnknown
	}
	if err = s.proveStopped(*prior.Helper); err != nil {
		return CleanupReport{}, err
	}
	if proof == nil {
		if prior.InputProfile != InputProfileSemantic && prior.InputProfile != InputProfileLaunch {
			return CleanupReport{}, ErrCleanupUnknown
		}
	} else if err = proof(ctx, copyLease(*prior.Lease), *prior.Helper); err != nil {
		return CleanupReport{}, errors.Join(ErrCleanupUnknown, err)
	}
	if err = ctx.Err(); err != nil {
		return CleanupReport{}, err
	}
	if err = s.proveStopped(*prior.Helper); err != nil {
		return CleanupReport{}, err
	}
	report := CleanupReport{InputInhibited: true, HelperStopped: true, Reason: reason, BusinessOutcomeUnknown: businessUnknown || prior.LastCleanup.BusinessOutcomeUnknown}
	prior.Lease = nil
	prior.Helper = nil
	prior.InputProfile = ""
	prior.LastCleanup = &report
	s.file = file
	s.state = prior
	err = s.persist()
	s.file = nil
	if err != nil {
		return CleanupReport{}, err
	}
	if err = syscall.Flock(fd, syscall.LOCK_UN); err != nil {
		return report, err
	}
	report.FenceReleased = true
	return report, nil
}
