//go:build darwin || linux

package keychain

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func adoptionFixtureEvidence(f *compositionFixture) (migrationPreparationPlan, migrationPreparationEvidence, []byte) {
	plan := preparationPlanFixture()
	plan.MutationRequirement = f.enrollment.worker.executorRequirement
	identity := []byte("synthetic-persistent-item")
	c := migrationCoordinator{options: f.enrollment.worker.options, record: &migrationJournalRecord{transitionID: strings.Repeat("e", 64), identity: identity}}
	evidence := migrationPreparationEvidence{IntentSHA256: migrationPreparationIntent(f.enrollment.worker, f.enrollment.template.oldConfigSHA256, plan), ConfigSHA256: f.enrollment.template.oldConfigSHA256, OptionsSHA256: migrationOptionsDigest(f.enrollment.worker.options), RuntimeManifestSHA256: plan.RuntimeManifestSHA256, MutationRequirement: plan.MutationRequirement, Transition: c.transition()}
	return plan, evidence, identity
}
func TestPreparedTransitionAdoptionRevalidatesUnderInstallerLeaseAndKeepsID(t *testing.T) {
	f := newCompositionFixture(t)
	plan, evidence, identity := adoptionFixtureEvidence(f)
	outer, _ := f.ctx.Deadline()
	until := outer.Add(-250 * time.Millisecond)
	checks := 0
	ctx, cancel, err := bindMigrationPreparation(f.ctx, f.composition, plan, evidence, identity, until, func(ctx context.Context) error { checks++; return f.composition.installer.check(ctx) })
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	deadline, _ := ctx.Deadline()
	if !deadline.Equal(until) {
		t.Fatal("prepared deadline not exact")
	}
	if _, _, err = bindMigrationPreparation(ctx, f.composition, plan, evidence, identity, until, func(context.Context) error { return nil }); err == nil {
		t.Fatal("preparation adopted twice")
	}
	done := fixtureCompositionAttest(f, migrationApprovalAttested)
	result, err := f.composition.execute(ctx)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if err != nil || result.State != migrationVerified || result.TransitionID != evidence.Transition.ID || f.executor.prepares != 1 || f.executor.commits != 1 || checks != 2 {
		t.Fatal("trusted transition not adopted once", result, err, checks)
	}
	record, err := f.acl.load(ctx)
	if err != nil || record == nil || record.transitionID != evidence.Transition.ID || !bytes.Equal(record.identity, identity) {
		t.Fatal("journal adopted another transition")
	}
}
func TestPreparedTransitionAdoptionRejectsMismatchesBeforeMetadata(t *testing.T) {
	for _, mode := range []string{"intent", "options", "config", "item", "transition", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			f := newCompositionFixture(t)
			plan, evidence, identity := adoptionFixtureEvidence(f)
			until, _ := f.ctx.Deadline()
			until = until.Add(-time.Millisecond)
			switch mode {
			case "intent":
				plan.RuntimeManifestSHA256 = strings.Repeat("0", 64)
			case "options":
				evidence.OptionsSHA256 = strings.Repeat("0", 64)
			case "config":
				evidence.ConfigSHA256 = strings.Repeat("0", 64)
			case "item":
				identity = []byte("other-item")
			case "transition":
				evidence.Transition.Binding = strings.Repeat("0", 64)
			case "deadline":
				until = until.Add(time.Hour)
			}
			if _, _, err := bindMigrationPreparation(f.ctx, f.composition, plan, evidence, identity, until, func(context.Context) error { return nil }); err == nil || f.executor.prepares != 0 || f.executor.commits != 0 {
				t.Fatal("changed preparation admitted")
			}
		})
	}
}
func TestPreparedTransitionAdoptionRefusesChangedItemConfigPriorJournalOrExtendedContext(t *testing.T) {
	for _, mode := range []string{"item", "config", "journal", "unclamped"} {
		t.Run(mode, func(t *testing.T) {
			f := newCompositionFixture(t)
			plan, evidence, identity := adoptionFixtureEvidence(f)
			until, _ := f.ctx.Deadline()
			until = until.Add(-250 * time.Millisecond)
			ctx, cancel, err := bindMigrationPreparation(f.ctx, f.composition, plan, evidence, identity, until, func(context.Context) error {
				if mode == "config" {
					return errMigrationUnavailable
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer cancel()
			if mode == "item" {
				f.executor.substitute = true
				f.executor.prepareHook = func(p *migrationPrepared) { p.identity = []byte("changed-item") }
			}
			if mode == "journal" {
				if err = f.acl.markUnknown(ctx, migrationJournalRecord{state: migrationUnknown, transitionID: strings.Repeat("9", 64), optionsSHA256: evidence.OptionsSHA256, identity: identity}); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "unclamped" {
				ctx = f.ctx
			}
			result, err := f.composition.execute(ctx)
			if err == nil || result.State == migrationVerified || f.executor.commits != 0 {
				t.Fatal("stale preparation reached commit", result, err)
			}
			if mode == "journal" {
				record, e := f.acl.load(ctx)
				if e != nil || record.transitionID != strings.Repeat("9", 64) {
					t.Fatal("prior journal rewritten")
				}
			}
		})
	}
}
