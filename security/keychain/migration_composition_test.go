//go:build darwin || linux

package keychain

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type compositionFixture struct {
	composition *migrationComposition
	executor    *migrationWorkerExecutorFixture
	authority   *migrationNativeAuthority
	enrollment  migrationCompositionEnrollment
	gates       migrationCompositionGates
	acl, stage  *fileMigrationJournal
	console     *net.UnixConn
	ctx         context.Context
}

func newCompositionFixture(t *testing.T) *compositionFixture {
	t.Helper()
	files, p, _ := migrationFileStageFixture(t)
	a, _, console, ctx := migrationAuthorityFixture(t)
	sendMigrationCredential(t, console)
	ctx, err := a.workerAuthority(ctx)
	if err != nil {
		t.Fatal(err)
	}
	acl, root := fileMigrationFixture(t)
	stage, err := newRuntimeStageJournal(filepath.Join(filepath.Dir(root), "mechanize-runtime-staging"))
	if err != nil {
		t.Fatal(err)
	}
	template := p
	template.transitionID = ""
	template.itemIdentity = nil
	config := migrationWorkerConfig{options: p.options, session: strings.Repeat("a", 64), executorRequirement: `identifier "com.viant.mechanize.custody-migration" and cdhash H"` + strings.Repeat("b", 40) + `"`}
	enrollment := migrationCompositionEnrollment{worker: config, template: template, candidateBinary: files.candidateBinary, candidateConfig: files.candidateConfig, canonicalConfig: files.config, backup: files.backup, aclJournalRoot: root, stageJournalRoot: stage.root}
	executor := &migrationWorkerExecutorFixture{migrationBackendFixture: &migrationBackendFixture{events: &[]string{}}}
	executor.commitHook = func() { executor.newPolicy = true }
	gates := migrationCompositionGates{self: func(context.Context) error { return nil }, code: files.code, quiescent: files.quiescent, runtimePrepared: func(context.Context) error { return nil }, runtimeReady: func(context.Context, migrationStagePlan) error { return nil }, keyReady: func(context.Context, migrationStagePlan) error { return nil }}
	transport, err := newMigrationApprovalTransport(a, config, acl)
	if err != nil {
		t.Fatal(err)
	}
	composition, err := newMigrationCompositionWith(ctx, a.workerAuthority, enrollment, executor, acl, stage, transport.approve, gates)
	if err != nil {
		t.Fatal(err)
	}
	return &compositionFixture{composition, executor, a, enrollment, gates, acl, stage, console, ctx}
}
func fixtureCompositionAttest(f *compositionFixture, decision byte) <-chan error {
	return runApprovalConsole(f.console, func(r migrationApprovalRequest, d [32]byte) error {
		record, err := f.acl.load(f.ctx)
		if err != nil || record == nil || record.state != migrationUnknown || record.transitionID != r.transition.ID || migrationDigest(record.identity) != r.binding.ItemReferenceSHA256 {
			return errors.New("no exact durable unknown barrier before attestation")
		}
		return writeMigrationApprovalResponse(f.console, decision, r.nonce, d)
	})
}
func TestCompositionJoinsFilesJournalsConsoleAttestationAndIsolatedCommit(t *testing.T) {
	f := newCompositionFixture(t)
	commit := f.executor.commitHook
	f.executor.commitHook = func() {
		ar, e1 := f.acl.load(f.ctx)
		sr, e2 := f.stage.load(f.ctx)
		if e1 != nil || e2 != nil || ar == nil || sr == nil || ar.state != migrationUnknown || sr.state != migrationUnknown || ar.transitionID != sr.transitionID {
			t.Fatal("commit escaped distinct durable barriers")
		}
		if migrationReadFixture(t, f.enrollment.worker.options.canonicalExecutable) != "new-binary" || migrationReadFixture(t, f.enrollment.canonicalConfig) != "new-config" {
			t.Fatal("ACL changed before checked staging")
		}
		if _, release, err := migrationPlacementLock(f.enrollment.worker.options.canonicalExecutable); err == nil {
			release()
			t.Fatal("commit did not hold installer exclusion")
		}
		commit()
	}
	done := fixtureCompositionAttest(f, migrationApprovalAttested)
	r, err := f.composition.execute(f.ctx)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if err != nil || r.State != migrationVerified || r.Scope != "custody-broker-config" || f.executor.commits != 1 || f.executor.pin != f.enrollment.worker.executorRequirement {
		t.Fatal("composition did not finish bounded scope", r, err)
	}
	ar, _ := f.acl.load(f.ctx)
	sr, _ := f.stage.load(f.ctx)
	if ar.state != migrationVerified || sr.state != migrationVerified {
		t.Fatal("final ledgers not verified")
	}
	if _, err = f.composition.execute(f.ctx); err == nil || f.executor.commits != 1 {
		t.Fatal("composition replayed")
	}
	if migrationReadFixture(t, filepath.Join(f.enrollment.backup, "mechanize")) != "old-binary" {
		t.Fatal("original backup missing")
	}
}
func TestCompositionDeclinedAttestationRetainsUnknownWithoutACLOrRollback(t *testing.T) {
	f := newCompositionFixture(t)
	done := fixtureCompositionAttest(f, migrationApprovalDeclined)
	r, err := f.composition.execute(f.ctx)
	<-done
	if err != errMigrationUnknown || r.State != migrationUnknown || f.executor.commits != 0 {
		t.Fatal("declined response changed ACL", r, err)
	}
	ar, _ := f.acl.load(f.ctx)
	sr, _ := f.stage.load(f.ctx)
	if ar == nil || sr == nil || ar.state != migrationUnknown || sr.state != migrationUnknown {
		t.Fatal("decline discarded write-ahead evidence")
	}
	if migrationReadFixture(t, f.enrollment.worker.options.canonicalExecutable) != "new-binary" || migrationReadFixture(t, filepath.Join(f.enrollment.backup, "mechanize")) != "old-binary" {
		t.Fatal("decline rolled files back or lost backup")
	}
	if _, err = f.composition.execute(f.ctx); err == nil {
		t.Fatal("decline replayed placement")
	}
}
func TestCompositionExplicitRuntimeAndKeyGates(t *testing.T) {
	for _, mode := range []string{"missing", "prepared", "runtime-ready", "key-ready"} {
		t.Run(mode, func(t *testing.T) {
			f := newCompositionFixture(t)
			gates := f.gates
			switch mode {
			case "missing":
				gates.keyReady = nil
			case "prepared":
				gates.runtimePrepared = func(context.Context) error { return errMigrationUnavailable }
			case "runtime-ready":
				gates.runtimeReady = func(context.Context, migrationStagePlan) error { return errMigrationUnavailable }
			case "key-ready":
				gates.keyReady = func(context.Context, migrationStagePlan) error { return errMigrationUnavailable }
			}
			transport, err := newMigrationApprovalTransport(f.authority, f.enrollment.worker, f.acl)
			if err != nil {
				t.Fatal(err)
			}
			c, err := newMigrationCompositionWith(f.ctx, f.authority.workerAuthority, f.enrollment, f.executor, f.acl, f.stage, transport.approve, gates)
			if mode == "missing" {
				if err != errMigrationUnavailable {
					t.Fatal("missing readiness gate admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var done <-chan error
			if mode != "prepared" {
				done = fixtureCompositionAttest(f, migrationApprovalAttested)
			}
			r, err := c.execute(f.ctx)
			if done != nil {
				<-done
			}
			if err == nil || r.State == migrationVerified {
				t.Fatal("missing full-runtime evidence claimed success")
			}
			if mode == "prepared" {
				if f.executor.prepares != 0 || f.executor.commits != 0 || migrationReadFixture(t, f.enrollment.worker.options.canonicalExecutable) != "old-binary" {
					t.Fatal("unprepared runtime mutated")
				}
				if _, e := os.Stat(f.enrollment.backup); !os.IsNotExist(e) {
					t.Fatal("unprepared runtime created backup")
				}
			} else {
				ar, _ := f.acl.load(f.ctx)
				sr, _ := f.stage.load(f.ctx)
				if ar.state != migrationVerified || sr.state != migrationUnknown {
					t.Fatal("readiness failure erased distinct ledger states")
				}
			}
		})
	}
}
func TestCompositionRestartReconcilesWithoutPreparationPlacementOrApproval(t *testing.T) {
	f := newCompositionFixture(t)
	done := fixtureCompositionAttest(f, migrationApprovalAttested)
	if _, err := f.composition.execute(f.ctx); err != nil {
		t.Fatal(err)
	}
	<-done
	gates := f.gates
	gates.runtimePrepared = func(context.Context) error { t.Fatal("restart attempted preparation"); return errMigrationUnavailable }
	c, err := newMigrationCompositionWith(f.ctx, f.authority.workerAuthority, f.enrollment, f.executor, f.acl, f.stage, func(context.Context, migrationWorkerApprovalBinding) error {
		t.Fatal("restart requested approval")
		return errMigrationUnavailable
	}, gates)
	if err != nil {
		t.Fatal(err)
	}
	prepares, commits := f.executor.prepares, f.executor.commits
	r, err := c.reconcile(f.ctx)
	if err != nil || r.State != migrationVerified || f.executor.prepares != prepares || f.executor.commits != commits {
		t.Fatal("restart did not perform read-only reconciliation", r, err)
	}
	if _, err = c.execute(f.ctx); err == nil {
		t.Fatal("reconciled composition replayed execution")
	}
}
func TestCompositionBarrierCannotAdoptExistingJournalOrAcknowledgeTwice(t *testing.T) {
	ctx := migrationFixtureContext(t, true)
	base, _ := fileMigrationFixture(t)
	r := fileMigrationRecord()
	first := &migrationCompositionJournal{base: base}
	if first.markUnknown(ctx, r) != errMigrationUnknown {
		t.Fatal("unprimed coordinator acknowledgement admitted")
	}
	if err := first.prime(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := first.markUnknown(ctx, r); err != nil {
		t.Fatal(err)
	}
	if first.markUnknown(ctx, r) != errMigrationUnknown {
		t.Fatal("barrier acknowledgement replayed")
	}
	restarted := &migrationCompositionJournal{base: base}
	if restarted.prime(ctx, r) != errMigrationUnknown {
		t.Fatal("existing unknown journal reused as a fresh operation")
	}
	actual, err := base.load(ctx)
	if err != nil || !sameCompositionRecord(actual, &r) {
		t.Fatal("refusal rewrote original evidence")
	}
}

func TestCompositionForeignCallerCannotBorrowConsoleAuthority(t *testing.T) {
	f := newCompositionFixture(t)
	principal, _ := auth.FromContext(f.ctx)
	principal.ClientID = "foreign-client"
	foreign := auth.WithPrincipal(f.ctx, principal)
	if _, err := f.composition.execute(foreign); err != errMigrationUnavailable || f.executor.prepares != 0 {
		t.Fatal("foreign caller borrowed native console owner")
	}
	if _, err := os.Stat(f.enrollment.backup); !os.IsNotExist(err) {
		t.Fatal("foreign caller staged files")
	}
}
