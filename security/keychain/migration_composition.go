//go:build darwin || linux

package keychain

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"

	"github.com/viant/mechanize/auth"
)

// Additional frozen signed enrollment for the bounded broker/config operation.
// Existing command/bootstrap fields do not implicitly authorize these paths.
type migrationCompositionEnrollment struct {
	worker                                                    migrationWorkerConfig
	unified                                                   *migrationRuntimeArtifact
	template                                                  migrationStagePlan
	candidateBinary, candidateConfig, canonicalConfig, backup string
	aclJournalRoot, stageJournalRoot                          string
}

// These are trusted native integration dependencies, never request arguments.
// Missing full-runtime or fresh key-readiness integration refuses construction.
// The composition itself stages only broker/config, so its receipt stays scoped.
type migrationCompositionGates struct {
	self            func(context.Context) error
	code            func(context.Context, string, string) error
	quiescent       func(context.Context) error
	runtimePrepared func(context.Context) error
	runtimeReady    func(context.Context, migrationStagePlan) error
	keyReady        func(context.Context, migrationStagePlan) error
}
type migrationCompositionReceipt struct {
	State        migrationState `json:"state"`
	TransitionID string         `json:"transitionId,omitempty"`
	Scope        string         `json:"scope"`
}
type migrationComposition struct {
	installer  *migrationInstaller
	backend    *migrationCompositionBackend
	acl, stage migrationJournal
	enrollment migrationCompositionEnrollment
}

func (*migrationComposition) String() string               { return "Signed custody and broker/config composition" }
func (*migrationComposition) GoString() string             { return "Signed custody and broker/config composition" }
func (*migrationComposition) MarshalJSON() ([]byte, error) { return []byte(`{"state":"private"}`), nil }

// Attestation requires the durable unknown barrier, while coordinator approval
// precedes its markUnknown call. This adapter writes that exact barrier before
// asking the console; the later coordinator call may consume it exactly once in
// this process. It never permits an existing/restarted journal to be replayed.
type migrationCompositionJournal struct {
	mu                  sync.Mutex
	base                migrationJournal
	primed              *migrationJournalRecord
	attempted, consumed bool
}

func sameCompositionRecord(a, b *migrationJournalRecord) bool {
	return a != nil && b != nil && a.transitionID == b.transitionID && a.optionsSHA256 == b.optionsSHA256 && bytes.Equal(a.identity, b.identity) && a.state == b.state
}
func (j *migrationCompositionJournal) load(ctx context.Context) (*migrationJournalRecord, error) {
	return j.base.load(ctx)
}
func (j *migrationCompositionJournal) prime(ctx context.Context, r migrationJournalRecord) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.attempted || r.state != migrationUnknown || migrationContext(ctx) != nil {
		return errMigrationUnavailable
	}
	j.attempted = true
	if j.base.markUnknown(ctx, r) != nil {
		return errMigrationUnknown
	}
	current, err := j.base.load(ctx)
	if err != nil || !sameCompositionRecord(current, &r) || migrationContext(ctx) != nil {
		return errMigrationUnknown
	}
	copy := r
	copy.identity = bytes.Clone(r.identity)
	j.primed = &copy
	return nil
}
func (j *migrationCompositionJournal) markUnknown(ctx context.Context, r migrationJournalRecord) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.consumed || j.primed == nil || !sameCompositionRecord(j.primed, &r) || migrationContext(ctx) != nil {
		return errMigrationUnknown
	}
	j.consumed = true
	current, err := j.base.load(ctx)
	if err != nil || !sameCompositionRecord(current, &r) || migrationContext(ctx) != nil {
		return errMigrationUnknown
	}
	return nil
}
func (j *migrationCompositionJournal) markVerified(ctx context.Context, r migrationJournalRecord) error {
	// Reconciliation can legitimately verify a prior unknown journal without this
	// process priming/dispatching. The base's exact record CAS remains authoritative.
	return j.base.markVerified(ctx, r)
}

type migrationCompositionBackend struct {
	executor             migrationWorkerExecutor
	authority            migrationWorkerAuthority
	config               migrationWorkerConfig
	gates                migrationCompositionGates
	owner                auth.Principal
	attestedIdentity     []byte
	attested, dispatched bool
}

func (b *migrationCompositionBackend) authorize(ctx context.Context) (context.Context, error) {
	if migrationContext(ctx) != nil || b.gates.self(ctx) != nil {
		return nil, errMigrationUnavailable
	}
	original, err := auth.FromContext(ctx)
	if err != nil || original.Namespace != b.owner.Namespace || original.ClientID != b.owner.ClientID {
		return nil, errMigrationUnavailable
	}
	authorized, err := b.authority(ctx)
	if err != nil || migrationContext(authorized) != nil {
		return nil, errMigrationUnavailable
	}
	p, err := auth.FromContext(authorized)
	a, _ := authorized.Deadline()
	d, _ := ctx.Deadline()
	if err != nil || p.Namespace != b.owner.Namespace || p.ClientID != b.owner.ClientID || a.After(d) {
		return nil, errMigrationUnavailable
	}
	return authorized, nil
}
func (b *migrationCompositionBackend) prepare(ctx context.Context, o migrationOptions) (*migrationPrepared, error) {
	ctx, err := b.authorize(ctx)
	if err != nil || o != b.config.options || b.gates.runtimePrepared(ctx) != nil {
		return nil, errMigrationUnavailable
	}
	return b.executor.prepare(ctx, o)
}
func (b *migrationCompositionBackend) verifyBeforeCommit(ctx context.Context, o migrationOptions, p *migrationPrepared) error {
	ctx, err := b.authorize(ctx)
	if err != nil || o != b.config.options {
		return errMigrationUnavailable
	}
	return b.executor.verifyBeforeCommit(ctx, o, p)
}
func (b *migrationCompositionBackend) commit(ctx context.Context, o migrationOptions, p *migrationPrepared) error {
	ctx, err := b.authorize(ctx)
	if err != nil || o != b.config.options || !b.attested || b.dispatched || p == nil || !bytes.Equal(p.identity, b.attestedIdentity) {
		return errMigrationUnavailable
	}
	if b.executor.verifyBeforeCommit(ctx, o, p) != nil || migrationContext(ctx) != nil {
		return errMigrationUnavailable
	}
	b.dispatched = true
	return b.executor.commitAsIsolatedHelper(ctx, o, p, b.config.executorRequirement)
}
func (b *migrationCompositionBackend) inspect(ctx context.Context, o migrationOptions, id []byte) (migrationInspection, error) {
	ctx, err := b.authorize(ctx)
	if err != nil || o != b.config.options {
		return migrationInspection{}, errMigrationUnavailable
	}
	return b.executor.inspect(ctx, o, id)
}

// Tests substitute only platform metadata/code checks; they still exercise real
// private journals, file exchange, native-console binary attestation and flock.
func newMigrationCompositionWith(ctx context.Context, authority migrationWorkerAuthority, enrollment migrationCompositionEnrollment, executor migrationWorkerExecutor,
	acl, stage migrationJournal, approval migrationWorkerApproval, gates migrationCompositionGates) (*migrationComposition, error) {
	if authority == nil || executor == nil || acl == nil || stage == nil || approval == nil || gates.self == nil || gates.code == nil || gates.quiescent == nil || gates.runtimePrepared == nil || gates.runtimeReady == nil || gates.keyReady == nil ||
		!validMigrationBootstrap(enrollment.worker, migrationOptionsDigest(enrollment.worker.options)) || enrollment.worker.expectedIdentity != nil || enrollment.template.options != enrollment.worker.options {
		return nil, errMigrationUnavailable
	}
	authorized, err := authority(ctx)
	if err != nil || migrationContext(authorized) != nil || gates.self(authorized) != nil {
		return nil, errMigrationUnavailable
	}
	owner, err := auth.FromContext(authorized)
	if err != nil || owner.ClientID == "" {
		return nil, errMigrationUnavailable
	}
	backend := &migrationCompositionBackend{executor: executor, authority: authority, config: enrollment.worker, gates: gates, owner: owner}
	barrier := &migrationCompositionJournal{base: acl}
	var coordinator *migrationCoordinator
	approve := func(ctx context.Context, t migrationTransition) (migrationApproval, error) {
		checked, err := backend.authorize(ctx)
		if err != nil || coordinator == nil || coordinator.record == nil || coordinator.transition() != t {
			return migrationApproval{}, errMigrationUnavailable
		}
		record := coordinator.recordCopy() // coordinator holds its mutex while invoking approval
		if barrier.prime(checked, record) != nil {
			return migrationApproval{}, errMigrationUnknown
		}
		var nonce [32]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return migrationApproval{}, errMigrationUnknown
		}
		binding := migrationWorkerApprovalBinding{Session: enrollment.worker.session, RequestID: hex.EncodeToString(nonce[:]), OptionsSHA256: migrationOptionsDigest(enrollment.worker.options), ExecutorRequirement: enrollment.worker.executorRequirement, ItemReferenceSHA256: migrationDigest(record.identity)}
		if approval(checked, binding) != nil {
			return migrationApproval{}, errMigrationUnknown
		}
		if _, err = backend.authorize(checked); err != nil {
			return migrationApproval{}, errMigrationUnknown
		}
		backend.attested = true
		backend.attestedIdentity = bytes.Clone(record.identity)
		return migrationApproval{approved: true, binding: t.Binding}, nil
	}
	coordinator, err = newMigrationCoordinator(enrollment.worker.options, backend, barrier, approve)
	if err != nil {
		return nil, errMigrationUnavailable
	}
	factory := func(ctx context.Context, p migrationStagePlan, check func() error) (*migrationStageController, error) {
		quiescent := func(ctx context.Context) error {
			authorized, e := backend.authorize(ctx)
			if e != nil {
				return e
			}
			return gates.quiescent(authorized)
		}
		complete := func(ctx context.Context, p migrationStagePlan) error {
			authorized, e := backend.authorize(ctx)
			if e != nil || gates.runtimeReady(authorized, p) != nil || gates.keyReady(authorized, p) != nil {
				return errMigrationUnavailable
			}
			return nil
		}
		if enrollment.unified != nil {
			app := enrollment.unified
			var files *migrationUnifiedStage
			var e error
			if p.updateConfig != "" {
				files, e = newMigrationUnifiedUpdateStage(p, *app, enrollment.candidateConfig, enrollment.canonicalConfig, enrollment.backup, quiescent, gates.code, complete, check)
			} else {
				files, e = newMigrationUnifiedStage(p, app.Candidate, app.Target, enrollment.candidateConfig, enrollment.canonicalConfig, enrollment.backup, app.New, app.NewRequirement, quiescent, gates.code, complete, check)
			}
			if e != nil {
				return nil, e
			}
			return newMigrationStageController(p, stage, files)
		}
		files, e := newMigrationFileStage(p, enrollment.candidateBinary, enrollment.candidateConfig, enrollment.canonicalConfig, enrollment.backup, quiescent, gates.code, complete, check)
		if e != nil {
			return nil, e
		}
		return newMigrationStageController(p, stage, files)
	}
	acquire := func(ctx context.Context) (func() error, func(), error) {
		if _, e := backend.authorize(ctx); e != nil {
			return nil, nil, e
		}
		return migrationPlacementLock(enrollment.template.configPath())
	}
	installer, err := newMigrationInstaller(coordinator, enrollment.template, factory, acquire, owner)
	if err != nil {
		return nil, errMigrationUnavailable
	}
	return &migrationComposition{installer: installer, backend: backend, acl: acl, stage: stage, enrollment: enrollment}, nil
}
func (c *migrationComposition) execute(ctx context.Context) (migrationCompositionReceipt, error) {
	if c == nil {
		return migrationCompositionReceipt{State: migrationBlocked, Scope: "custody-broker-config"}, errMigrationUnavailable
	}
	authorized, err := c.backend.authorize(ctx)
	if err != nil {
		return migrationCompositionReceipt{State: migrationBlocked, Scope: "custody-broker-config"}, err
	}
	r, err := c.installer.execute(authorized)
	return migrationCompositionReceipt{State: r.State, TransitionID: r.TransitionID, Scope: "custody-broker-config"}, err
}

// Restart restoration binds both durable ledgers before the installer's fresh
// exclusion-protected reconciliation. No preparation, placement or commit occurs.
func (c *migrationComposition) reconcile(ctx context.Context) (migrationCompositionReceipt, error) {
	if c == nil {
		return migrationCompositionReceipt{State: migrationBlocked, Scope: "custody-broker-config"}, errMigrationUnavailable
	}
	authorized, err := c.backend.authorize(ctx)
	if err != nil {
		return migrationCompositionReceipt{State: migrationUnknown, Scope: "custody-broker-config"}, errMigrationUnknown
	}
	c.installer.mu.Lock()
	{
		ar, e1 := c.acl.load(authorized)
		sr, e2 := c.stage.load(authorized)
		p := c.enrollment.template
		if e1 != nil || e2 != nil || ar == nil || sr == nil || ar.optionsSHA256 != migrationOptionsDigest(p.options) || !validMasterIdentity(ar.identity) || !validMigrationID(ar.transitionID) || !bytes.Equal(ar.identity, sr.identity) || ar.transitionID != sr.transitionID {
			c.installer.mu.Unlock()
			return migrationCompositionReceipt{State: migrationUnknown, Scope: "custody-broker-config"}, errMigrationUnknown
		}
		p.transitionID = ar.transitionID
		p.itemIdentity = bytes.Clone(ar.identity)
		if sr.optionsSHA256 != migrationStageDigest(p) {
			c.installer.mu.Unlock()
			return migrationCompositionReceipt{State: migrationUnknown, Scope: "custody-broker-config"}, errMigrationUnknown
		}
		restored, e := c.installer.stageFactory(authorized, p, func() error { return errMigrationUnavailable })
		if e != nil {
			c.installer.mu.Unlock()
			return migrationCompositionReceipt{State: migrationUnknown, Scope: "custody-broker-config"}, errMigrationUnknown
		}
		if (ar.state != migrationUnknown && ar.state != migrationVerified) || (sr.state != migrationUnknown && sr.state != migrationVerified) {
			c.installer.mu.Unlock()
			return migrationCompositionReceipt{State: migrationUnknown, Scope: "custody-broker-config"}, errMigrationUnknown
		}
		c.installer.coordinator.mu.Lock()
		c.installer.coordinator.release()
		snapshot := *ar
		snapshot.identity = bytes.Clone(ar.identity)
		c.installer.coordinator.record = &snapshot
		c.installer.coordinator.state = ar.state
		c.installer.coordinator.mu.Unlock()
		c.installer.stage = restored
		c.installer.started = true
	}
	c.installer.mu.Unlock()
	r, err := c.installer.reconcile(authorized)
	return migrationCompositionReceipt{State: r.State, TransitionID: r.TransitionID, Scope: "custody-broker-config"}, err
}
