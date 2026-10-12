//go:build darwin || linux

package keychain

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

type stageFixtureBackend struct {
	events                    *[]string
	placeError, completeError bool
}

func (s stageFixtureBackend) verifyBeforePlacement(context.Context, migrationStagePlan) error {
	*s.events = append(*s.events, "verify-old")
	return nil
}
func (s stageFixtureBackend) place(context.Context, migrationStagePlan) error {
	*s.events = append(*s.events, "place")
	if s.placeError {
		return errors.New("private-canary")
	}
	return nil
}
func (s stageFixtureBackend) verifyComplete(context.Context, migrationStagePlan) error {
	*s.events = append(*s.events, "verify-complete")
	if s.completeError {
		return errors.New("private-canary")
	}
	return nil
}
func stageFixturePlan() migrationStagePlan {
	return migrationStagePlan{options: migrationFixtureOptions(), oldBinarySHA256: strings.Repeat("1", 64), newBinarySHA256: strings.Repeat("2", 64), oldConfigSHA256: strings.Repeat("3", 64), newConfigSHA256: strings.Repeat("4", 64), transitionID: strings.Repeat("5", 64), itemIdentity: []byte("opaque-public-fixture-item")}
}
func TestRuntimeStagingBarrierPrecedesPlacementAndRequiresFullVerification(t *testing.T) {
	_, _, journal, events := migrationFixture(t)
	controller, err := newMigrationStageController(stageFixturePlan(), journal, stageFixtureBackend{events: events})
	if err != nil {
		t.Fatal(err)
	}
	ctx := migrationFixtureContext(t, true)
	if err = controller.stage(ctx); err != nil {
		t.Fatal(err)
	}
	if journal.record == nil || journal.record.state != migrationUnknown || controller.state != migrationUnknown {
		t.Fatal("file placement cleared uncertainty")
	}
	want := []string{"load", "verify-old", "journal-unknown", "place"}
	if strings.Join(*events, ",") != strings.Join(want, ",") {
		t.Fatal("placement preceded write-ahead")
	}
	if err = controller.reconcile(ctx); err != nil || controller.state != migrationVerified || journal.record.state != migrationVerified {
		t.Fatal("full verification did not retain terminal receipt")
	}
	if err = controller.stage(ctx); !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("verified placement replayed")
	}
}
func TestRuntimeStagingFailureAndRestartCannotReplay(t *testing.T) {
	_, _, journal, events := migrationFixture(t)
	plan := stageFixturePlan()
	ctx := migrationFixtureContext(t, true)
	first, _ := newMigrationStageController(plan, journal, stageFixtureBackend{events: events, placeError: true})
	if err := first.stage(ctx); !errors.Is(err, errMigrationUnknown) {
		t.Fatal("failed placement not unknown")
	}
	second, _ := newMigrationStageController(plan, journal, stageFixtureBackend{events: events, completeError: true})
	before := len(*events)
	if err := second.stage(ctx); !errors.Is(err, errMigrationUnknown) || len(*events) != before+1 {
		t.Fatal("restart replayed placement")
	}
	if err := second.reconcile(ctx); !errors.Is(err, errMigrationUnknown) || journal.record.state != migrationUnknown {
		t.Fatal("failed full verification cleared barrier")
	}
}
func TestRuntimeStagingJournalFailureCannotPlaceAndRejectsForeignPlan(t *testing.T) {
	_, _, journal, events := migrationFixture(t)
	journal.unknownError = true
	plan := stageFixturePlan()
	controller, _ := newMigrationStageController(plan, journal, stageFixtureBackend{events: events})
	if err := controller.stage(migrationFixtureContext(t, true)); !errors.Is(err, errMigrationUnknown) {
		t.Fatal("uncertain journal not unknown")
	}
	for _, event := range *events {
		if event == "place" {
			t.Fatal("placement followed failed journal")
		}
	}
	_, _, journal, events = migrationFixture(t)
	other := plan
	other.newBinarySHA256 = strings.Repeat("a", 64)
	journal.record = &migrationJournalRecord{state: migrationUnknown, transitionID: plan.transitionID, optionsSHA256: migrationStageDigest(plan), identity: plan.itemIdentity}
	foreign, _ := newMigrationStageController(other, journal, stageFixtureBackend{events: events})
	if err := foreign.reconcile(migrationFixtureContext(t, true)); !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("foreign stage plan reconciled")
	}
}
func TestRuntimeStagingUsesSeparatePrivateJournalWithoutKeychain(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".secret", "mechanize-runtime-staging")
	journal, err := newRuntimeStageJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = newFileMigrationJournal(path); !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("ACL journal accepted staging namespace")
	}
	events := []string{}
	controller, _ := newMigrationStageController(stageFixturePlan(), journal, stageFixtureBackend{events: &events})
	ctx := migrationFixtureContext(t, true)
	if err = controller.stage(ctx); err != nil {
		t.Fatal(err)
	}
	restarted, err := newRuntimeStageJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := restarted.load(ctx)
	if err != nil || stored == nil || stored.state != migrationUnknown {
		t.Fatal("staging barrier not durable")
	}
	if err = controller.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
}
