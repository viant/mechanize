package keychain

import (
	"bytes"
	"context"
	"sync"

	"github.com/viant/mechanize/auth"
)

// Trusted installer factory, not a decoded caller-selected backend. It binds
// checked artifact hashes to the exact prepared item and transition before any
// canonical placement. A production entrypoint must supply native authority,
// the isolated writer, bound approval, durable journals and real file hooks.
type migrationInstallStageFactory func(context.Context, migrationStagePlan, func() error) (*migrationStageController, error)

// The trusted installer pins the canonical lock path outside request decoding.
// Any nonnil release must release exactly the lease acquired by this call.
type migrationInstallAcquire func(context.Context) (check func() error, release func(), err error)
type migrationHeldLease struct {
	mu      sync.Mutex
	check   func() error
	release func()
	closed  bool
}

func (l *migrationHeldLease) verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.check == nil {
		return errMigrationUnavailable
	}
	return l.check()
}
func (l *migrationHeldLease) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.closed = true
	if l.release != nil {
		l.release()
	}
}

type migrationInstallerLeaseKey struct{}
type migrationInstallerLeaseContext struct {
	owner *migrationInstaller
	lease *migrationHeldLease
}

type migrationInstaller struct {
	mu                  sync.Mutex
	coordinator         *migrationCoordinator
	template            migrationStagePlan
	stageFactory        migrationInstallStageFactory
	acquire             migrationInstallAcquire
	namespace, clientID string
	started             bool
	stage               *migrationStageController
}

func newMigrationInstaller(coordinator *migrationCoordinator, template migrationStagePlan, factory migrationInstallStageFactory, acquire migrationInstallAcquire, owner auth.Principal) (*migrationInstaller, error) {
	if coordinator == nil || factory == nil || acquire == nil || owner.Validate() != nil || owner.ClientID == "" || !owner.HasScope("consent:admin") || coordinator.options != template.options ||
		!validMigrationID(template.oldBinarySHA256) || !validMigrationID(template.newBinarySHA256) || template.oldBinarySHA256 == template.newBinarySHA256 ||
		!validMigrationID(template.oldConfigSHA256) || !validMigrationID(template.newConfigSHA256) || template.oldConfigSHA256 == template.newConfigSHA256 || template.transitionID != "" || template.itemIdentity != nil {
		return nil, errMigrationUnavailable
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if _, owned := coordinator.backend.(*migrationInstallBackend); owned {
		return nil, errMigrationUnavailable
	}
	installer := &migrationInstaller{coordinator: coordinator, template: template, stageFactory: factory, acquire: acquire, namespace: owner.Namespace, clientID: owner.ClientID}
	coordinator.backend = &migrationInstallBackend{backend: coordinator.backend, owner: installer}
	approval := coordinator.approve
	coordinator.approve = func(ctx context.Context, t migrationTransition) (migrationApproval, error) {
		if installer.check(ctx) != nil {
			return migrationApproval{}, errMigrationUnavailable
		}
		result, err := approval(ctx, t)
		if err != nil || installer.check(ctx) != nil {
			return migrationApproval{}, errMigrationUnavailable
		}
		return result, nil
	}
	return installer, nil
}

func (i *migrationInstaller) authorize(ctx context.Context) error {
	if i == nil || migrationContext(ctx) != nil {
		return errMigrationUnavailable
	}
	p, e := auth.FromContext(ctx)
	if e != nil || p.Namespace != i.namespace || p.ClientID != i.clientID {
		return errMigrationUnavailable
	}
	return nil
}

func (i *migrationInstaller) check(ctx context.Context) error {
	if i.authorize(ctx) != nil {
		return errMigrationUnavailable
	}
	held, ok := ctx.Value(migrationInstallerLeaseKey{}).(*migrationInstallerLeaseContext)
	if !ok || held.owner != i || held.lease == nil || held.lease.verify() != nil {
		return errMigrationUnavailable
	}
	return nil
}
func (i *migrationInstaller) hold(ctx context.Context) (context.Context, func(), error) {
	if i.authorize(ctx) != nil {
		return nil, nil, errMigrationUnavailable
	}
	check, release, err := i.acquire(ctx)
	lease := &migrationHeldLease{check: check, release: release}
	if err != nil || check == nil || release == nil || i.authorize(ctx) != nil || lease.verify() != nil {
		lease.close()
		return nil, nil, errMigrationUnavailable
	}
	return context.WithValue(ctx, migrationInstallerLeaseKey{}, &migrationInstallerLeaseContext{owner: i, lease: lease}), lease.close, nil
}
func (i *migrationInstaller) makeStage(ctx context.Context, p migrationStagePlan) (*migrationStageController, error) {
	if i.check(ctx) != nil {
		return nil, errMigrationUnavailable
	}
	input := p
	input.itemIdentity = bytes.Clone(p.itemIdentity)
	s, err := i.stageFactory(ctx, input, func() error { return i.check(ctx) })
	if err != nil || s == nil || i.check(ctx) != nil || migrationStageDigest(s.plan) != migrationStageDigest(p) || !s.matching(&migrationJournalRecord{state: migrationUnknown, transitionID: p.transitionID, optionsSHA256: migrationStageDigest(p), identity: p.itemIdentity}) {
		return nil, errMigrationUnavailable
	}
	s.backend = &migrationInstallStageBackend{backend: s.backend, owner: i}
	return s, nil
}

// Guard each actual backend call, including commit after approval/journaling,
// so losing the lease within a phase cannot silently authorize the next effect.
type migrationInstallBackend struct {
	backend migrationBackend
	owner   *migrationInstaller
}

func (b *migrationInstallBackend) prepare(ctx context.Context, o migrationOptions) (*migrationPrepared, error) {
	if b.owner.check(ctx) != nil {
		return nil, errMigrationUnavailable
	}
	p, err := b.backend.prepare(ctx, o)
	if err != nil || b.owner.check(ctx) != nil {
		return p, errMigrationUnavailable
	}
	return p, nil
}
func (b *migrationInstallBackend) verifyBeforeCommit(ctx context.Context, o migrationOptions, p *migrationPrepared) error {
	if b.owner.check(ctx) != nil {
		return errMigrationUnavailable
	}
	if b.backend.verifyBeforeCommit(ctx, o, p) != nil || b.owner.check(ctx) != nil {
		return errMigrationUnavailable
	}
	return nil
}
func (b *migrationInstallBackend) commit(ctx context.Context, o migrationOptions, p *migrationPrepared) error {
	if b.owner.check(ctx) != nil {
		return errMigrationUnavailable
	}
	if b.backend.commit(ctx, o, p) != nil || b.owner.check(ctx) != nil {
		return errMigrationUnknown
	}
	return nil
}
func (b *migrationInstallBackend) inspect(ctx context.Context, o migrationOptions, id []byte) (migrationInspection, error) {
	if b.owner.check(ctx) != nil {
		return migrationInspection{}, errMigrationUnavailable
	}
	r, err := b.backend.inspect(ctx, o, id)
	if err != nil || b.owner.check(ctx) != nil {
		return migrationInspection{}, errMigrationUnavailable
	}
	return r, nil
}

type migrationInstallStageBackend struct {
	backend migrationStageBackend
	owner   *migrationInstaller
}

func (b *migrationInstallStageBackend) verifyBeforePlacement(ctx context.Context, p migrationStagePlan) error {
	if b.owner.check(ctx) != nil {
		return errMigrationUnavailable
	}
	if b.backend.verifyBeforePlacement(ctx, p) != nil || b.owner.check(ctx) != nil {
		return errMigrationUnavailable
	}
	return nil
}
func (b *migrationInstallStageBackend) place(ctx context.Context, p migrationStagePlan) error {
	if b.owner.check(ctx) != nil {
		return errMigrationUnavailable
	}
	if b.backend.place(ctx, p) != nil || b.owner.check(ctx) != nil {
		return errMigrationUnknown
	}
	return nil
}
func (b *migrationInstallStageBackend) verifyComplete(ctx context.Context, p migrationStagePlan) error {
	if b.owner.check(ctx) != nil {
		return errMigrationUnavailable
	}
	if b.backend.verifyComplete(ctx, p) != nil || b.owner.check(ctx) != nil {
		return errMigrationUnavailable
	}
	return nil
}

// Execute submits each phase once. Successful file placement is never custody
// success: only independently verified ACL/item equality AND final file/config/
// readiness evidence allow the staging journal to retain a verified receipt.
func (i *migrationInstaller) execute(ctx context.Context) (migrationReceipt, error) {
	if i.authorize(ctx) != nil {
		return migrationReceipt{State: migrationBlocked}, errMigrationUnavailable
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.started || i.authorize(ctx) != nil {
		return migrationReceipt{State: migrationBlocked}, errMigrationUnavailable
	}
	i.started = true
	held, release, err := i.hold(ctx)
	if err != nil {
		return migrationReceipt{State: migrationBlocked}, errMigrationUnavailable
	}
	defer release()
	ctx = held
	defer func() { i.coordinator.mu.Lock(); i.coordinator.release(); i.coordinator.mu.Unlock() }()
	r, e := i.coordinator.prepare(ctx)
	if e != nil {
		return r, e
	}
	i.coordinator.mu.Lock()
	p := i.template
	if i.coordinator.state != migrationPreparedState || !i.coordinator.preparedIdentityMatches() {
		i.coordinator.mu.Unlock()
		return migrationReceipt{State: migrationBlocked}, errMigrationUnavailable
	}
	p.transitionID = i.coordinator.record.transitionID
	p.itemIdentity = append([]byte(nil), i.coordinator.record.identity...)
	i.coordinator.mu.Unlock()
	if i.check(ctx) != nil {
		return migrationReceipt{State: migrationBlocked, TransitionID: p.transitionID}, errMigrationUnavailable
	}
	s, e := i.makeStage(ctx, p)
	if e != nil {
		return migrationReceipt{State: migrationBlocked, TransitionID: p.transitionID}, errMigrationUnavailable
	}
	i.stage = s
	if e = s.stage(ctx); e != nil {
		return migrationReceipt{State: s.state, TransitionID: p.transitionID}, e
	}
	// The placement journal remains unknown until BOTH later verification phases.
	if i.check(ctx) != nil {
		return migrationReceipt{State: migrationUnknown, TransitionID: p.transitionID}, errMigrationUnknown
	}
	r, e = i.coordinator.commit(ctx)
	if e != nil || r.State != migrationVerified {
		return migrationReceipt{State: migrationUnknown, TransitionID: p.transitionID}, errMigrationUnknown
	}
	if i.check(ctx) != nil || s.reconcile(ctx) != nil || i.check(ctx) != nil {
		return migrationReceipt{State: migrationUnknown, TransitionID: p.transitionID}, errMigrationUnknown
	}
	return migrationReceipt{State: migrationVerified, TransitionID: p.transitionID}, nil
}

// Explicit reconciliation contains no preparation, file placement, approval or
// ACL dispatch. Restart callers must restore checked matching journals/plan in
// their trusted constructors; missing staging evidence cannot be guessed.
func (i *migrationInstaller) reconcile(ctx context.Context) (migrationReceipt, error) {
	if i.authorize(ctx) != nil {
		return migrationReceipt{State: migrationBlocked}, errMigrationUnavailable
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stage == nil {
		return migrationReceipt{State: migrationBlocked}, errMigrationUnavailable
	}
	held, release, err := i.hold(ctx)
	if err != nil {
		return migrationReceipt{State: migrationUnknown}, errMigrationUnknown
	}
	defer release()
	ctx = held
	fresh, err := i.makeStage(ctx, i.stage.plan)
	if err != nil {
		return migrationReceipt{State: migrationUnknown, TransitionID: i.stage.plan.transitionID}, errMigrationUnknown
	}
	i.stage = fresh
	i.coordinator.mu.Lock()
	known := i.coordinator.state == migrationVerified && i.coordinator.record != nil
	var r migrationReceipt
	var e error
	if known {
		r = i.coordinator.receipt()
		current, err := i.coordinator.backend.inspect(ctx, i.coordinator.options, bytes.Clone(i.coordinator.record.identity))
		if err != nil || !current.exactNewPolicy || !bytes.Equal(current.identity, i.coordinator.record.identity) || migrationContext(ctx) != nil {
			r.State = migrationUnknown
			e = errMigrationUnknown
		}
	}
	i.coordinator.mu.Unlock()
	if !known {
		r, e = i.coordinator.reconcile(ctx)
	}
	if e != nil || r.State != migrationVerified {
		if e == nil {
			e = errMigrationUnknown
		}
		return r, e
	}
	if i.check(ctx) != nil || i.stage.reconcile(ctx) != nil || i.check(ctx) != nil {
		return migrationReceipt{State: migrationUnknown, TransitionID: r.TransitionID}, errMigrationUnknown
	}
	return r, nil
}

func (*migrationInstaller) String() string               { return "Mechanize checked runtime installation" }
func (*migrationInstaller) MarshalJSON() ([]byte, error) { return []byte(`{"state":"private"}`), nil }
