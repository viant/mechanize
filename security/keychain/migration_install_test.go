//go:build darwin || linux

package keychain

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/viant/mechanize/auth"
)

func installerFixture(t *testing.T, failPlacement, failComplete bool) (*migrationInstaller, *migrationBackendFixture, *migrationJournalFixture, *migrationJournalFixture, context.Context) {
	t.Helper()
	c, b, acl, events := migrationFixture(t)
	ctx := migrationFixtureContext(t, true)
	owner, _ := auth.FromContext(ctx)
	owner.ClientID = "fixture-console"
	ctx = auth.WithPrincipal(ctx, owner)
	template := stageFixturePlan()
	template.transitionID = ""
	template.itemIdentity = nil
	stageJournal := &migrationJournalFixture{events: events}
	factory := func(ctx context.Context, p migrationStagePlan, check func() error) (*migrationStageController, error) {
		if p.transitionID != c.record.transitionID || migrationDigest(p.itemIdentity) != migrationDigest(c.record.identity) {
			t.Fatal("staging lost prepared item/transition binding")
		}
		return newMigrationStageController(p, stageJournal, stageFixtureBackend{events: events, placeError: failPlacement, completeError: failComplete})
	}
	i, e := newMigrationInstaller(c, template, factory, (&installerLeaseFixture{}).acquire, owner)
	if e != nil {
		t.Fatal(e)
	}
	return i, b, acl, stageJournal, ctx
}

func TestInstallerBothJournalsMustVerifyBeforeSuccess(t *testing.T) {
	i, b, acl, stage, ctx := installerFixture(t, false, false)
	b.commitHook = func() {
		if stage.record == nil || stage.record.state != migrationUnknown || acl.record == nil || acl.record.state != migrationUnknown {
			t.Fatal("ACL dispatched without both durable barriers")
		}
	}
	r, e := i.execute(ctx)
	if e != nil || r.State != migrationVerified || b.commits != 1 || stage.record.state != migrationVerified || acl.record.state != migrationVerified {
		t.Fatal("installation not completely verified", r, e)
	}
	if _, e = i.execute(ctx); e == nil || b.commits != 1 {
		t.Fatal("installation replayed")
	}
}
func TestInstallerPartialPlacementCannotChangeKeychainOrReplay(t *testing.T) {
	i, b, acl, stage, ctx := installerFixture(t, true, false)
	r, e := i.execute(ctx)
	if !errors.Is(e, errMigrationUnknown) || r.State != migrationUnknown || b.commits != 0 || acl.record != nil || stage.record.state != migrationUnknown || b.disposals != 1 {
		t.Fatal("partial files did not retain barrier", r, e)
	}
	if _, e = i.execute(ctx); e == nil || b.prepares != 1 {
		t.Fatal("partial installation replayed")
	}
}
func TestInstallerFileReadinessFailureRetainsVerifiedACLAndUnknownStaging(t *testing.T) {
	i, b, acl, stage, ctx := installerFixture(t, false, true)
	r, e := i.execute(ctx)
	if !errors.Is(e, errMigrationUnknown) || r.State != migrationUnknown || b.commits != 1 || acl.record.state != migrationVerified || stage.record.state != migrationUnknown {
		t.Fatal("file readiness failure lost distinct custody states", r, e)
	}
	if _, e = i.reconcile(ctx); !errors.Is(e, errMigrationUnknown) || b.commits != 1 {
		t.Fatal("reconciliation changed ACL or claimed completion", e)
	}
}
func TestInstallerForeignAdministratorCannotStartPreparedOwnerWork(t *testing.T) {
	i, b, _, _, ctx := installerFixture(t, false, false)
	p, _ := auth.FromContext(ctx)
	p.ClientID = "foreign-client"
	foreign := auth.WithPrincipal(ctx, p)
	if _, e := i.execute(foreign); e == nil || b.prepares != 0 {
		t.Fatal("foreign client started work")
	}
	if _, e := i.execute(ctx); e != nil {
		t.Fatal("rejection consumed owner's installation", e)
	}
}
func TestInstallerFactoryCannotSubstitutePreparedIdentity(t *testing.T) {
	i, b, _, _, ctx := installerFixture(t, false, false)
	i.stageFactory = func(ctx context.Context, p migrationStagePlan, check func() error) (*migrationStageController, error) {
		p.itemIdentity = []byte("substituted-fixture-item")
		return newMigrationStageController(p, &migrationJournalFixture{events: &[]string{}}, stageFixtureBackend{events: &[]string{}})
	}
	_, e := i.execute(ctx)
	if e == nil || b.commits != 0 || b.disposals != 1 {
		t.Fatal("substituted stage proceeded")
	}
}
func TestInstallerTemplateCannotClaimPriorItemOrTransition(t *testing.T) {
	i, _, _, _, ctx := installerFixture(t, false, false)
	p, _ := auth.FromContext(ctx)
	for _, mode := range []string{"item", "transition", "hash"} {
		template := i.template
		switch mode {
		case "item":
			template.itemIdentity = []byte("caller-item")
		case "transition":
			template.transitionID = strings.Repeat("a", 64)
		case "hash":
			template.newBinarySHA256 = template.oldBinarySHA256
		}
		if _, e := newMigrationInstaller(i.coordinator, template, i.stageFactory, i.acquire, p); e == nil {
			t.Fatal("untrusted template accepted", mode)
		}
	}
}

// Only a test dependency; production acquisition is the descriptor-checked flock.
type installerLeaseFixture struct {
	mu                 sync.Mutex
	held, lost         bool
	acquires, releases int
}

func (l *installerLeaseFixture) acquire(context.Context) (func() error, func(), error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held {
		return nil, nil, errMigrationUnavailable
	}
	l.held = true
	l.acquires++
	return func() error {
		l.mu.Lock()
		defer l.mu.Unlock()
		if !l.held || l.lost {
			return errMigrationUnavailable
		}
		return nil
	}, func() { l.mu.Lock(); defer l.mu.Unlock(); l.releases++; l.held = false }, nil
}
func (l *installerLeaseFixture) lose() { l.mu.Lock(); defer l.mu.Unlock(); l.lost = true }
func (l *installerLeaseFixture) assertReleased(t *testing.T) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held || l.releases != l.acquires {
		t.Fatalf("lease lifecycle acquires=%d releases=%d held=%v", l.acquires, l.releases, l.held)
	}
}

type installerStageHook struct {
	migrationStageBackend
	afterPlace, beforeComplete func()
}

func (b installerStageHook) place(ctx context.Context, p migrationStagePlan) error {
	err := b.migrationStageBackend.place(ctx, p)
	if b.afterPlace != nil {
		b.afterPlace()
	}
	return err
}
func (b installerStageHook) verifyComplete(ctx context.Context, p migrationStagePlan) error {
	if b.beforeComplete != nil {
		b.beforeComplete()
	}
	return b.migrationStageBackend.verifyComplete(ctx, p)
}

func TestInstallerLeaseFailureBlocksEveryNextPhaseAndReleases(t *testing.T) {
	for _, phase := range []string{"prepare", "placement", "approval", "commit", "readiness"} {
		t.Run(phase, func(t *testing.T) {
			i, b, acl, stage, ctx := installerFixture(t, false, false)
			lease := &installerLeaseFixture{}
			i.acquire = lease.acquire
			switch phase {
			case "prepare":
				b.prepareHook = func(*migrationPrepared) { lease.lose() }
			case "placement":
				factory := i.stageFactory
				i.stageFactory = func(ctx context.Context, p migrationStagePlan, check func() error) (*migrationStageController, error) {
					s, e := factory(ctx, p, check)
					if e == nil {
						s.backend = installerStageHook{migrationStageBackend: s.backend, afterPlace: lease.lose}
					}
					return s, e
				}
			case "approval":
				approval := i.coordinator.approve
				i.coordinator.approve = func(ctx context.Context, t migrationTransition) (migrationApproval, error) {
					r, e := approval(ctx, t)
					lease.lose()
					return r, e
				}
			case "commit":
				b.commitHook = lease.lose
			case "readiness":
				factory := i.stageFactory
				i.stageFactory = func(ctx context.Context, p migrationStagePlan, check func() error) (*migrationStageController, error) {
					s, e := factory(ctx, p, check)
					if e == nil {
						s.backend = installerStageHook{migrationStageBackend: s.backend, beforeComplete: lease.lose}
					}
					return s, e
				}
			}
			result, err := i.execute(ctx)
			if err == nil || result.State == migrationVerified {
				t.Fatal("lost exclusion yielded success")
			}
			lease.assertReleased(t)
			if phase == "prepare" || phase == "placement" || phase == "approval" {
				if b.commits != 0 {
					t.Fatal("lost lease dispatched ACL")
				}
			}
			if phase == "prepare" && stage.record != nil {
				t.Fatal("preparation failure staged files")
			}
			if phase == "readiness" && (acl.record == nil || acl.record.state != migrationVerified || stage.record.state != migrationUnknown) {
				t.Fatal("readiness lost separate ledger states")
			}
		})
	}
}
func TestInstallerAcquisitionRefusalDoesNotPrepareAndReleasesReturnedLease(t *testing.T) {
	for _, mode := range []string{"error", "nilcheck", "nilrelease", "badcheck"} {
		t.Run(mode, func(t *testing.T) {
			i, b, _, _, ctx := installerFixture(t, false, false)
			releases := 0
			i.acquire = func(context.Context) (func() error, func(), error) {
				check := func() error { return nil }
				release := func() { releases++ }
				var err error
				switch mode {
				case "error":
					err = errors.New("private acquisition failure")
				case "nilcheck":
					check = nil
				case "nilrelease":
					release = nil
				case "badcheck":
					check = func() error { return errMigrationUnavailable }
				}
				return check, release, err
			}
			if _, err := i.execute(ctx); err == nil || b.prepares != 0 {
				t.Fatal("acquisition failure prepared item")
			}
			expected := 1
			if mode == "nilrelease" {
				expected = 0
			}
			if releases != expected {
				t.Fatal("lease not released exactly once", releases)
			}
		})
	}
}
func TestInstallerHeldCheckExpiresAndReconciliationReacquires(t *testing.T) {
	i, b, _, _, ctx := installerFixture(t, false, false)
	lease := &installerLeaseFixture{}
	i.acquire = lease.acquire
	var checks []func() error
	factory := i.stageFactory
	i.stageFactory = func(ctx context.Context, p migrationStagePlan, check func() error) (*migrationStageController, error) {
		checks = append(checks, check)
		return factory(ctx, p, check)
	}
	if _, err := i.execute(ctx); err != nil {
		t.Fatal(err)
	}
	lease.assertReleased(t)
	if checks[0]() == nil {
		t.Fatal("released execution check remains valid")
	}
	if _, err := i.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	lease.assertReleased(t)
	if len(checks) != 2 || checks[0]() == nil || checks[1]() == nil || b.commits != 1 || b.prepares != 1 || lease.acquires != 2 {
		t.Fatal("reconciliation reused lease or mutated")
	}
}
func TestInstallerRealFileLeaseExcludesCompetitorThroughCommitAndReadiness(t *testing.T) {
	files, plan, ctx := migrationFileStageFixture(t)
	c, b, _, events := migrationFixture(t)
	c.options = plan.options
	owner, _ := auth.FromContext(ctx)
	owner.ClientID = "fixture-console"
	ctx = auth.WithPrincipal(ctx, owner)
	template := plan
	template.transitionID = ""
	template.itemIdentity = nil
	stageJournal := &migrationJournalFixture{events: events}
	heldChecks := 0
	excluded := func() {
		t.Helper()
		_, release, err := migrationPlacementLock(plan.options.canonicalExecutable)
		if err == nil {
			release()
			t.Fatal("competing installer acquired active lease")
		}
		heldChecks++
	}
	b.prepareHook = func(*migrationPrepared) { excluded() }
	b.commitHook = excluded
	acquired, released := 0, 0
	acquire := func(ctx context.Context) (func() error, func(), error) {
		if migrationContext(ctx) != nil {
			return nil, nil, errMigrationUnavailable
		}
		check, release, err := migrationPlacementLock(plan.options.canonicalExecutable)
		if err != nil {
			return nil, nil, err
		}
		acquired++
		return check, func() { released++; release() }, nil
	}
	factory := func(ctx context.Context, p migrationStagePlan, check func() error) (*migrationStageController, error) {
		backend, err := newMigrationFileStage(p, files.candidateBinary, files.candidateConfig, files.config, files.backup, func(context.Context) error { excluded(); return nil }, files.code, func(context.Context, migrationStagePlan) error { excluded(); return nil }, check)
		if err != nil {
			return nil, err
		}
		return newMigrationStageController(p, stageJournal, backend)
	}
	i, err := newMigrationInstaller(c, template, factory, acquire, owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = i.execute(ctx); err != nil {
		t.Fatal(err)
	}
	if heldChecks < 4 || acquired != 1 || released != 1 {
		t.Fatal("lease not held through phases")
	}
	check, release, err := migrationPlacementLock(plan.options.canonicalExecutable)
	if err != nil {
		t.Fatal("lease retained after execution", err)
	}
	if check() != nil {
		t.Fatal("post-operation lease invalid")
	}
	release()
	if _, err = i.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if acquired != 2 || released != 2 || b.commits != 1 {
		t.Fatal("reconciliation failed lease lifecycle")
	}
	if migrationReadFixture(t, filepath.Join(files.backup, "mechanize")) != "old-binary" {
		t.Fatal("reconciliation changed backup")
	}
}

func TestInstallerFactoryFailureAndReconcileLossReleaseLease(t *testing.T) {
	t.Run("factory", func(t *testing.T) {
		i, b, _, _, ctx := installerFixture(t, false, false)
		lease := &installerLeaseFixture{}
		i.acquire = lease.acquire
		i.stageFactory = func(context.Context, migrationStagePlan, func() error) (*migrationStageController, error) {
			return nil, errors.New("private stage construction error")
		}
		if _, err := i.execute(ctx); err == nil || b.commits != 0 || b.disposals != 1 {
			t.Fatal("factory failure did not stop and dispose")
		}
		lease.assertReleased(t)
	})
	t.Run("reconcile", func(t *testing.T) {
		i, b, _, _, ctx := installerFixture(t, false, false)
		lease := &installerLeaseFixture{}
		i.acquire = lease.acquire
		if _, err := i.execute(ctx); err != nil {
			t.Fatal(err)
		}
		inspections := b.inspections
		lease.lose()
		if _, err := i.reconcile(ctx); err != errMigrationUnknown || b.inspections != inspections || b.commits != 1 {
			t.Fatal("lost reconciliation lease performed verification or mutation")
		}
		lease.assertReleased(t)
	})
}
