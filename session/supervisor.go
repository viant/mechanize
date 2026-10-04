// Package session fences physical desktop input across broker processes.
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/viant/mechanize/auth"
)

var ErrContended = errors.New("desktop input fence is held by another broker/helper")
var ErrOldHelperAlive = errors.New("old helper is alive; epoch transfer requires proof of stop")
var ErrCleanupUnknown = errors.New("prior helper cleanup is uncertain; held-input reconciliation required before epoch transfer")
var ErrNoLease = errors.New("held desktop fence and helper identity required")

type ProcessIdentity struct {
	PID        int    `json:"pid"`
	StartToken string `json:"startToken"`
	Executable string `json:"executable"`
	UID        uint32 `json:"uid"`
}
type ProcessInspector func(int) (ProcessIdentity, bool, error)
type Scope struct {
	AllApplications bool     `json:"allApplications,omitempty"`
	AllowedBundles  []string `json:"allowedBundles"`
}

var concreteBundle = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+$`)

// Normalize makes desktop-wide access explicit and keeps exact bundle targets.
// An inventory, empty restricted scope or a wildcard cannot mint authority.
func (scope Scope) Normalize() (Scope, error) {
	if scope.AllApplications {
		if len(scope.AllowedBundles) != 0 {
			return Scope{}, errors.New("all-applications scope cannot carry restricted bundles")
		}
		return Scope{AllApplications: true, AllowedBundles: []string{}}, nil
	}
	if len(scope.AllowedBundles) < 1 || len(scope.AllowedBundles) > 64 {
		return Scope{}, errors.New("restricted app scope requires 1...64 explicit bundles")
	}
	copy := append([]string(nil), scope.AllowedBundles...)
	sort.Strings(copy)
	for i, bundle := range copy {
		if !validConcreteBundle(bundle) || i > 0 && copy[i-1] == bundle {
			return Scope{}, errors.New("invalid or duplicate concrete app scope")
		}
	}
	return Scope{AllowedBundles: copy}, nil
}
func validConcreteBundle(bundle string) bool {
	return len(bundle) > 0 && len(bundle) <= 255 && concreteBundle.MatchString(bundle)
}
func (scope Scope) Validate() error { _, err := scope.Normalize(); return err }
func (scope Scope) AllowsBundle(bundle string) bool {
	if !validConcreteBundle(bundle) {
		return false
	}
	normalized, err := scope.Normalize()
	if err != nil {
		return false
	}
	if normalized.AllApplications {
		return true
	}
	for _, allowed := range normalized.AllowedBundles {
		if allowed == bundle {
			return true
		}
	}
	return false
}
func (scope Scope) Equal(other Scope) bool {
	left, err := scope.Normalize()
	if err != nil {
		return false
	}
	right, err := other.Normalize()
	return err == nil && reflect.DeepEqual(left, right)
}

type Lease struct {
	ID         string `json:"id"`
	Generation uint64 `json:"generation"`
	Owner      string `json:"owner"`
	Scope      Scope  `json:"scope"`
}
type CleanupReport struct {
	InputInhibited bool   `json:"inputInhibited"`
	HelperStopped  bool   `json:"helperStopped"`
	FenceReleased  bool   `json:"fenceReleased"`
	UnknownInputs  bool   `json:"unknownInputs"`
	Reason         string `json:"reason,omitempty"`
	// Physical cleanup does not resolve uncertain application effects.
	BusinessOutcomeUnknown bool `json:"businessOutcomeUnknown,omitempty"`
}
type Options struct {
	LockPath string
	// HelperExecutable must be the explicit absolute helper image accepted by
	// enrollment. Signing/audit verification is additional production policy.
	HelperExecutable string
	Inspect          ProcessInspector
	// Never blindly kill a PID from disk. This optional recovery hook must inspect
	// identity/audit policy before stopping a previously enrolled orphan.
	StopOrphan func(context.Context, ProcessIdentity) error
}

// InputProfile is recorded with an enrolled helper before dispatch. Only the
// semantic and launch profiles exclude all raw key/button posting authority.
type InputProfile string

const (
	InputProfileRaw      InputProfile = "raw"
	InputProfileSemantic InputProfile = "semantic"
	InputProfileLaunch   InputProfile = "launch"
)

type record struct {
	InputProfile InputProfile     `json:"inputProfile,omitempty"`
	Generation   uint64           `json:"generation"`
	Lease        *Lease           `json:"lease,omitempty"`
	Helper       *ProcessIdentity `json:"helper,omitempty"`
	LastCleanup  *CleanupReport   `json:"lastCleanup,omitempty"`
}
type Supervisor struct {
	mu      sync.Mutex
	options Options
	file    *os.File
	state   record
	stop    func(context.Context) (CleanupReport, error)
}

func NewSupervisor(options Options) (*Supervisor, error) {
	if !filepath.IsAbs(options.LockPath) || !filepath.IsAbs(options.HelperExecutable) {
		return nil, errors.New("absolute desktop lock and explicit helper executable required")
	}
	if options.Inspect == nil {
		executable, err := filepath.EvalSymlinks(options.HelperExecutable)
		if err != nil {
			return nil, fmt.Errorf("enrolled helper executable: %w", err)
		}
		options.HelperExecutable = executable
		options.Inspect = InspectProcess
	}
	return &Supervisor{options: options}, nil
}
func actor(ctx context.Context, p auth.Principal) error {
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || !actual.HasScope("desktop:control") {
		return auth.ErrUnauthorized
	}
	return nil
}
func (s *Supervisor) Acquire(ctx context.Context, p auth.Principal, scope Scope) (Lease, error) {
	if err := actor(ctx, p); err != nil {
		return Lease{}, err
	}
	normalized, err := scope.Normalize()
	if err != nil {
		return Lease{}, err
	}
	scope = normalized
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		if s.state.Lease != nil && s.state.Lease.Owner == p.Namespace {
			if !s.state.Lease.Scope.Equal(scope) {
				return Lease{}, errors.New("held lease scope differs; close and reacquire explicitly")
			}
			return copyLease(*s.state.Lease), nil
		}
		return Lease{}, ErrContended
	}
	if err := ctx.Err(); err != nil {
		return Lease{}, err
	}
	parent := filepath.Dir(s.options.LockPath)
	info, err := os.Lstat(parent)
	if err != nil {
		return Lease{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return Lease{}, errors.New("desktop lock directory must be private (0700)")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Getuid()) {
		return Lease{}, errors.New("desktop lock directory owner mismatch")
	}
	fd, err := syscall.Open(s.options.LockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return Lease{}, err
	}
	file := os.NewFile(uintptr(fd), s.options.LockPath)
	success := false
	defer func() {
		if !success {
			file.Close()
		}
	}()
	info, err = file.Stat()
	if err != nil {
		return Lease{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm()&0077 != 0 || !info.Mode().IsRegular() || stat.Nlink != 1 {
		return Lease{}, errors.New("unsafe desktop lock file")
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if err == syscall.EWOULDBLOCK {
			return Lease{}, ErrContended
		}
		return Lease{}, err
	}
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil {
		return Lease{}, err
	}
	if len(data) > 65536 {
		return Lease{}, errors.New("desktop fence record too large")
	}
	var previous record
	if len(data) > 0 {
		if err = json.Unmarshal(data, &previous); err != nil {
			return Lease{}, errors.New("desktop fence record corrupt; no epoch transfer")
		}
	}
	if previous.LastCleanup != nil && previous.LastCleanup.UnknownInputs {
		return Lease{}, ErrCleanupUnknown
	}
	if previous.Helper != nil {
		if err = s.proveStopped(*previous.Helper); errors.Is(err, ErrOldHelperAlive) && s.options.StopOrphan != nil {
			if err = s.options.StopOrphan(ctx, *previous.Helper); err != nil {
				return Lease{}, err
			}
			err = s.proveStopped(*previous.Helper)
		}
		if err != nil {
			return Lease{}, err
		}
	}
	if previous.Generation >= uint64(^uint(0)>>1) {
		return Lease{}, errors.New("desktop epoch exhausted")
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return Lease{}, err
	}
	lease := Lease{ID: hex.EncodeToString(random[:]), Generation: previous.Generation + 1, Owner: p.Namespace, Scope: scope}
	s.file = file
	s.state = record{Generation: lease.Generation, Lease: &lease}
	if err = s.persist(); err != nil {
		s.file = nil
		return Lease{}, err
	}
	success = true
	return copyLease(lease), nil
}
func copyLease(lease Lease) Lease {
	lease.Scope.AllowedBundles = append([]string{}, lease.Scope.AllowedBundles...)
	return lease
}
func (s *Supervisor) persist() error {
	data, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	if _, err = s.file.Seek(0, 0); err != nil {
		return err
	}
	if err = s.file.Truncate(0); err != nil {
		return err
	}
	if _, err = s.file.Write(data); err != nil {
		return err
	}
	return s.file.Sync()
}
func (s *Supervisor) proveStopped(old ProcessIdentity) error {
	actual, alive, err := s.options.Inspect(old.PID)
	if err != nil {
		return fmt.Errorf("helper stop proof unavailable: %w", err)
	}
	if alive && actual.StartToken == old.StartToken {
		return ErrOldHelperAlive
	}
	return nil
}

// FenceFile is inherited by the helper so broker death cannot free the physical
// lock while an old helper still lives. Do not close, unlock or replace this file.
func (s *Supervisor) FenceFile(ctx context.Context, p auth.Principal) (*os.File, error) {
	if err := actor(ctx, p); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil || s.state.Lease == nil || s.state.Lease.Owner != p.Namespace {
		return nil, ErrNoLease
	}
	return s.file, nil
}

// AttachHelper records a verified PID/start identity before granting dispatch.
// stop must inhibit input, stop and reap this exact helper with a deadline.
func (s *Supervisor) AttachHelper(ctx context.Context, p auth.Principal, identity ProcessIdentity, stop func(context.Context) (CleanupReport, error)) error {
	return s.AttachHelperProfile(ctx, p, identity, InputProfileRaw, stop)
}

// AttachHelperProfile records the immutable launch profile of the verified
// executable, never a mutable current broker preference. The host must pass the
// same profile used to start that helper, after verifying executable/identity.
func (s *Supervisor) AttachHelperProfile(ctx context.Context, p auth.Principal, identity ProcessIdentity, profile InputProfile, stop func(context.Context) (CleanupReport, error)) error {
	if err := actor(ctx, p); err != nil {
		return err
	}
	if profile != InputProfileRaw && profile != InputProfileSemantic && profile != InputProfileLaunch {
		return ErrNoLease
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil || s.state.Lease == nil || s.state.Lease.Owner != p.Namespace || s.state.Helper != nil || stop == nil {
		return ErrNoLease
	}
	actual, alive, err := s.options.Inspect(identity.PID)
	if err != nil {
		return err
	}
	if !alive || identity.StartToken == "" || actual != identity || actual.UID != uint32(os.Getuid()) || filepath.Clean(actual.Executable) != filepath.Clean(s.options.HelperExecutable) {
		return errors.New("helper process enrollment identity mismatch")
	}
	s.state.Helper = &identity
	s.state.InputProfile = profile
	s.stop = stop
	if err = s.persist(); err != nil {
		s.state.Helper = nil
		s.state.InputProfile = ""
		s.stop = nil
		return err
	}
	return nil
}
func (s *Supervisor) Lease(ctx context.Context, p auth.Principal) (Lease, error) {
	if err := actor(ctx, p); err != nil {
		return Lease{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil || s.state.Lease == nil || s.state.Lease.Owner != p.Namespace || s.state.Helper == nil {
		return Lease{}, ErrNoLease
	}
	actual, alive, err := s.options.Inspect(s.state.Helper.PID)
	if err != nil {
		return Lease{}, err
	}
	if !alive || actual != *s.state.Helper {
		return Lease{}, ErrNoLease
	}
	lease := *s.state.Lease
	lease.Scope.AllowedBundles = append([]string{}, lease.Scope.AllowedBundles...)
	return lease, nil
}

// RetainUnknown records uncertainty even when launch identity could not be
// attached. A process restart must not turn that missing identity into a clean
// desktop. It retains the physical fence and requires explicit reconciliation.
func (s *Supervisor) RetainUnknown(ctx context.Context, p auth.Principal, report CleanupReport) error {
	if err := actor(ctx, p); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil || s.state.Lease == nil || s.state.Lease.Owner != p.Namespace {
		return ErrNoLease
	}
	report.UnknownInputs = true
	report.FenceReleased = false
	s.state.LastCleanup = &report
	return s.persist()
}

func (s *Supervisor) Close(ctx context.Context) (CleanupReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	report := CleanupReport{}
	if s.file == nil {
		return CleanupReport{InputInhibited: true, HelperStopped: true, FenceReleased: true}, nil
	}
	if s.state.Helper == nil && s.state.LastCleanup != nil && s.state.LastCleanup.UnknownInputs {
		return *s.state.LastCleanup, ErrCleanupUnknown
	}
	retainUnknown := func(cause error) (CleanupReport, error) {
		report.UnknownInputs = true
		report.FenceReleased = false
		s.state.LastCleanup = &report
		// Keep the original lease/helper record and flock. Persist the barrier
		// before returning so process death cannot turn uncertain cleanup into
		// permission to acquire a fresh generation.
		return report, errors.Join(cause, s.persist())
	}
	if s.state.Helper != nil {
		if s.stop != nil {
			bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			type outcome struct {
				report CleanupReport
				err    error
			}
			results := make(chan outcome, 1)
			go func() { report, err := s.stop(bounded); results <- outcome{report, err} }()
			select {
			case result := <-results:
				report = result.report
				if result.err != nil {
					report.UnknownInputs = true
					report.Reason = result.err.Error()
					return retainUnknown(result.err)
				}
			case <-bounded.Done():
				report.UnknownInputs = true
				report.Reason = "bounded helper teardown expired; fence retained"
				return retainUnknown(bounded.Err())
			}
		}
		if err := s.proveStopped(*s.state.Helper); err != nil {
			report.UnknownInputs = true
			report.HelperStopped = false
			return retainUnknown(err)
		}
		report.HelperStopped = true
	} else {
		report.InputInhibited = true
		report.HelperStopped = true
	}
	s.state.LastCleanup = &report
	s.state.Lease = nil
	s.state.Helper = nil
	s.state.InputProfile = ""
	if err := s.persist(); err != nil {
		return report, err
	}
	if err := syscall.Flock(int(s.file.Fd()), syscall.LOCK_UN); err != nil {
		return report, err
	}
	err := s.file.Close()
	s.file = nil
	s.stop = nil
	report.FenceReleased = err == nil
	return report, err
}
