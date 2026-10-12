//go:build darwin || linux

package keychain

import (
	"bytes"
	"context"
	"time"

	"github.com/viant/mechanize/auth"
)

// Created only by authenticated native composition wiring from independently
// verified preparation evidence. Never decoded directly as an approval claim.
type migrationPreparationAdoption struct {
	evidence            migrationPreparationEvidence
	identity            []byte
	deadline            time.Time
	namespace, clientID string
	frozen              func(context.Context) error
	used                bool
}

// Bind before execute, then use ONLY the returned shortened context. Preparation
// itself still happens afresh through the installer's real held lease/backend.
// expectedPlan and frozen are trusted current installation/manifest bindings,
// not fields accepted from a tool request or the later approval challenge.
func bindMigrationPreparation(ctx context.Context, composition *migrationComposition, expectedPlan migrationPreparationPlan,
	evidence migrationPreparationEvidence, identity []byte, deadline time.Time, frozen func(context.Context) error) (context.Context, context.CancelFunc, error) {
	if migrationContext(ctx) != nil || composition == nil || composition.installer == nil || frozen == nil || !expectedPlan.valid() || !validMasterIdentity(identity) || !deadline.After(time.Now()) {
		return nil, nil, errMigrationUnavailable
	}
	outer, ok := ctx.Deadline()
	if !ok || deadline.After(outer) {
		return nil, nil, errMigrationUnavailable
	}
	owner, err := auth.FromContext(ctx)
	if err != nil || owner.ClientID == "" {
		return nil, nil, errMigrationUnavailable
	}
	expectedIntent := migrationPreparationIntent(composition.enrollment.worker, composition.enrollment.template.oldConfigSHA256, expectedPlan)
	if expectedPlan.MutationRequirement != composition.enrollment.worker.executorRequirement {
		return nil, nil, errMigrationUnavailable
	}
	c := composition.installer.coordinator
	if c == nil || evidence.IntentSHA256 != expectedIntent || evidence.ConfigSHA256 != composition.enrollment.template.oldConfigSHA256 || evidence.OptionsSHA256 != migrationOptionsDigest(c.options) || evidence.MutationRequirement != composition.enrollment.worker.executorRequirement || !validMigrationID(evidence.RuntimeManifestSHA256) || !validMigrationID(evidence.Transition.ID) || evidence.Transition.ItemReferenceSHA256 != migrationDigest(identity) {
		return nil, nil, errMigrationUnavailable
	}
	expected := migrationCoordinator{options: c.options, record: &migrationJournalRecord{transitionID: evidence.Transition.ID, identity: identity}}
	if expected.transition() != evidence.Transition {
		return nil, nil, errMigrationUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	installed, ok := c.backend.(*migrationInstallBackend)
	if !ok || installed.owner != composition.installer || c.state != migrationIdle || c.record != nil || c.prepared != nil || c.adoption != nil {
		return nil, nil, errMigrationUnavailable
	}
	c.adoption = &migrationPreparationAdoption{evidence: evidence, identity: bytes.Clone(identity), deadline: deadline, namespace: owner.Namespace, clientID: owner.ClientID, frozen: frozen}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	return bounded, cancel, nil
}
func (a *migrationPreparationAdoption) check(ctx context.Context, c *migrationCoordinator, fresh bool) error {
	if a == nil || migrationContext(ctx) != nil || !time.Now().Before(a.deadline) {
		return errMigrationUnavailable
	}
	limit, ok := ctx.Deadline()
	if !ok || limit.After(a.deadline) {
		return errMigrationUnavailable
	}
	owner, err := auth.FromContext(ctx)
	if err != nil || owner.Namespace != a.namespace || owner.ClientID != a.clientID {
		return errMigrationUnavailable
	}
	installed, ok := c.backend.(*migrationInstallBackend)
	if !ok || installed.owner == nil || installed.owner.coordinator != c || installed.owner.check(ctx) != nil || migrationOptionsDigest(c.options) != a.evidence.OptionsSHA256 {
		return errMigrationUnavailable
	}
	if fresh {
		if a.used || a.frozen(ctx) != nil {
			return errMigrationUnavailable
		}
	} else {
		if !a.used || c.record == nil || c.record.transitionID != a.evidence.Transition.ID || !bytes.Equal(c.record.identity, a.identity) || c.transition() != a.evidence.Transition {
			return errMigrationUnavailable
		}
	}
	return nil
}
func (a *migrationPreparationAdoption) take(ctx context.Context, c *migrationCoordinator, identity []byte) (string, error) {
	if a.check(ctx, c, true) != nil || !bytes.Equal(identity, a.identity) {
		return "", errMigrationUnavailable
	}
	a.used = true
	return a.evidence.Transition.ID, nil
}
