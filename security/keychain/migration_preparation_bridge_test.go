package keychain

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func preparationPlanFixture() migrationPreparationPlan {
	return migrationPreparationPlan{MutationExecutable: "/fixture/private/worker", MutationRequirement: `identifier "com.viant.mechanize.custody-migration" and cdhash H"` + strings.Repeat("4", 40) + `"`, MutationSHA256: strings.Repeat("5", 64), RuntimeManifestSHA256: strings.Repeat("6", 64)}
}
func TestReadOnlyPreparationBindsActualSameItemUnderLease(t *testing.T) {
	w, backend, _ := migrationWorkerFixture(t)
	ctx := migrationFixtureContext(t, true)
	channel := migrationWorkerChannel(migrationWorkerWire(t, w, "prepare", "close"))
	held := false
	released := 0
	runtime := migrationPreparationRuntime{authority: func(ctx context.Context) (context.Context, error) { return ctx, nil }, metadata: func(ctx context.Context, o migrationOptions) (*migrationPrepared, error) {
		if !held {
			t.Fatal("metadata escaped lease")
		}
		return backend.prepare(ctx, o)
	}, frozen: func(context.Context) error { return nil }, acquire: func(context.Context) (func() error, func(), error) {
		held = true
		return func() error {
			if !held {
				return errMigrationUnavailable
			}
			return nil
		}, func() { held = false; released++ }, nil
	}}
	plan := preparationPlanFixture()
	digest := strings.Repeat("7", 64)
	if err := serveMigrationPreparation(ctx, channel, w.config, digest, plan, runtime); err != nil {
		t.Fatal(err)
	}
	if backend.prepares != 2 || backend.commits != 0 || backend.disposals != 2 || released != 1 || held {
		t.Fatal("preparation was not bounded/read-only", backend.prepares, backend.commits, backend.disposals, released)
	}
	reader := bytes.NewReader(channel.outputBytes())
	var response migrationPreparationResponse
	if readMigrationWorkerFrame(reader, &response) != nil || response.Status != "prepared" || response.Evidence == nil || !validMasterIdentity(response.Identity) {
		t.Fatal("missing prepared metadata")
	}
	evidence := response.Evidence
	if evidence.IntentSHA256 != migrationPreparationIntent(w.config, digest, plan) || evidence.ConfigSHA256 != digest || evidence.OptionsSHA256 != migrationOptionsDigest(w.config.options) || evidence.Transition.ItemReferenceSHA256 != migrationDigest(response.Identity) {
		t.Fatal("metadata binding changed")
	}
	c := migrationCoordinator{options: w.config.options, record: &migrationJournalRecord{transitionID: evidence.Transition.ID, identity: response.Identity}}
	if c.transition() != evidence.Transition {
		t.Fatal("generated transition format changed")
	}
	response = migrationPreparationResponse{}
	if readMigrationWorkerFrame(reader, &response) != nil || response.Status != "closed" || response.Evidence != nil {
		t.Fatal("close not canonical")
	}
}
func TestReadOnlyPreparationRejectsMutationVerbsBeforeMetadata(t *testing.T) {
	for _, op := range []string{"commit", "verify", "inspect"} {
		t.Run(op, func(t *testing.T) {
			w, backend, _ := migrationWorkerFixture(t)
			calls := 0
			runtime := migrationPreparationRuntime{authority: func(ctx context.Context) (context.Context, error) { return ctx, nil }, metadata: backend.prepare, frozen: func(context.Context) error { return nil }, acquire: func(context.Context) (func() error, func(), error) {
				calls++
				return func() error { return nil }, func() {}, nil
			}}
			channel := migrationWorkerChannel(migrationWorkerWire(t, w, op))
			if serveMigrationPreparation(migrationFixtureContext(t, true), channel, w.config, strings.Repeat("7", 64), preparationPlanFixture(), runtime) == nil || calls != 0 || backend.prepares != 0 || backend.commits != 0 {
				t.Fatal("read-only branch admitted mutation path")
			}
		})
	}
}
func TestReadOnlyPreparationRejectsStaleConfigItemLeaseAndAuthority(t *testing.T) {
	for _, mode := range []string{"config", "item", "lease", "authority", "repeat"} {
		t.Run(mode, func(t *testing.T) {
			w, backend, _ := migrationWorkerFixture(t)
			reads := 0
			checks := 0
			releases := 0
			runtime := migrationPreparationRuntime{authority: func(ctx context.Context) (context.Context, error) {
				if mode == "authority" {
					return nil, errors.New("private")
				}
				return ctx, nil
			}, metadata: func(ctx context.Context, o migrationOptions) (*migrationPrepared, error) {
				reads++
				p, e := backend.prepare(ctx, o)
				if mode == "item" && reads == 2 {
					p.identity = []byte("other-item")
				}
				return p, e
			}, frozen: func(context.Context) error {
				if mode == "config" {
					return errMigrationUnavailable
				}
				return nil
			}, acquire: func(context.Context) (func() error, func(), error) {
				return func() error {
					checks++
					if mode == "lease" && checks > 1 {
						return errMigrationUnavailable
					}
					return nil
				}, func() { releases++ }, nil
			}}
			ops := []string{"prepare", "close"}
			if mode == "repeat" {
				ops = []string{"prepare", "prepare"}
			}
			channel := migrationWorkerChannel(migrationWorkerWire(t, w, ops...))
			if serveMigrationPreparation(migrationFixtureContext(t, true), channel, w.config, strings.Repeat("7", 64), preparationPlanFixture(), runtime) == nil || backend.commits != 0 {
				t.Fatal("unsafe read-only preparation accepted")
			}
			if mode != "authority" && releases != 1 {
				t.Fatal("lease retained after refusal")
			}
		})
	}
}
func TestSignedPreparationModeIsClosedAndCannotBeReconciliation(t *testing.T) {
	v := packagedFixture()
	plan := preparationPlanFixture()
	v.Preparation = &plan
	if _, err := decodeMigrationPackagedEnrollment(encodePackaged(v)); err != nil {
		t.Fatal(err)
	}
	v.ExpectedIdentity = []byte("prior-reference")
	if _, err := decodeMigrationPackagedEnrollment(encodePackaged(v)); err == nil {
		t.Fatal("preparation widened into reconciliation")
	}
	v.ExpectedIdentity = nil
	v.Preparation.MutationRequirement = "untrusted"
	if _, err := decodeMigrationPackagedEnrollment(encodePackaged(v)); err == nil {
		t.Fatal("invalid mutation role accepted")
	}
}
