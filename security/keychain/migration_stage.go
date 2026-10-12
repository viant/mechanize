package keychain

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"sync"
)

// Private frozen installation metadata only. Configuration is represented by
// hashes, never by token/key-bearing configuration bodies.
type migrationStagePlan struct {
	options                                migrationOptions
	oldBinarySHA256, newBinarySHA256       string
	oldConfigSHA256, newConfigSHA256       string
	transitionID                           string
	itemIdentity                           []byte
	unifiedInventorySHA256                 string
	updateConfig, updateOldInventorySHA256 string
	preinstalledUnifiedApp                 bool
}

func validMigrationStagePlan(p migrationStagePlan) bool {
	return validMigrationOptions(p.options) && ((p.updateConfig != "" && validUnifiedUpdateConfig(p.options.canonicalExecutable, p.updateConfig) && p.options.newCanonicalExecutable == "" && !p.preinstalledUnifiedApp && validMigrationID(p.unifiedInventorySHA256) && validMigrationID(p.updateOldInventorySHA256)) || (p.updateConfig == "" && p.updateOldInventorySHA256 == "" && ((p.options.newCanonicalExecutable == "" && p.unifiedInventorySHA256 == "" && !p.preinstalledUnifiedApp) || (p.options.newCanonicalExecutable != "" && validMigrationID(p.unifiedInventorySHA256))))) && filepath.IsAbs(p.options.canonicalExecutable) && validMigrationID(p.oldBinarySHA256) && validMigrationID(p.newBinarySHA256) && p.oldBinarySHA256 != p.newBinarySHA256 && validMigrationID(p.oldConfigSHA256) && validMigrationID(p.newConfigSHA256) && p.oldConfigSHA256 != p.newConfigSHA256 && validMigrationID(p.transitionID) && validMasterIdentity(p.itemIdentity)
}
func migrationStageDigest(p migrationStagePlan) string {
	fields := []string{"mechanize-runtime-staging-v1", migrationOptionsDigest(p.options), p.oldBinarySHA256, p.newBinarySHA256, p.oldConfigSHA256, p.newConfigSHA256}
	if p.options.newCanonicalExecutable != "" {
		fields = append(fields, "mechanize-unified-app-placement-v2", p.unifiedInventorySHA256)
		if p.preinstalledUnifiedApp {
			fields = append(fields, "preinstalled-unified-app-v1")
		}
	}
	if p.updateConfig != "" {
		fields = append(fields, unifiedUpdateMode, p.updateConfig, p.updateOldInventorySHA256, p.unifiedInventorySHA256)
	}
	encoded, _ := json.Marshal(fields)
	return migrationDigest(encoded)
}

// Placement must retain checked backups and quiesce owned runtime/native work.
// Verification must freshly prove same-item/full-new-policy, exact staged code,
// config hashes and local key readiness. Neither hook may return private values.
// This interface does not itself implement file moves or Keychain mutations.
type migrationStageBackend interface {
	verifyBeforePlacement(context.Context, migrationStagePlan) error
	place(context.Context, migrationStagePlan) error
	verifyComplete(context.Context, migrationStagePlan) error
}
type migrationStageController struct {
	mu      sync.Mutex
	plan    migrationStagePlan
	journal migrationJournal
	backend migrationStageBackend
	state   migrationState
}

func newMigrationStageController(plan migrationStagePlan, journal migrationJournal, backend migrationStageBackend) (*migrationStageController, error) {
	if !validMigrationStagePlan(plan) || journal == nil || backend == nil {
		return nil, errMigrationUnavailable
	}
	plan.itemIdentity = bytes.Clone(plan.itemIdentity)
	return &migrationStageController{plan: plan, journal: journal, backend: backend, state: migrationIdle}, nil
}
func (s *migrationStageController) planCopy() migrationStagePlan {
	copy := s.plan
	copy.itemIdentity = bytes.Clone(s.plan.itemIdentity)
	return copy
}
func (s *migrationStageController) record() migrationJournalRecord {
	return migrationJournalRecord{state: migrationUnknown, transitionID: s.plan.transitionID, optionsSHA256: migrationStageDigest(s.plan), identity: bytes.Clone(s.plan.itemIdentity)}
}
func (s *migrationStageController) matching(record *migrationJournalRecord) bool {
	return record != nil && record.transitionID == s.plan.transitionID && record.optionsSHA256 == migrationStageDigest(s.plan) && bytes.Equal(record.identity, s.plan.itemIdentity) && (record.state == migrationUnknown || record.state == migrationVerified)
}
func (s *migrationStageController) stage(ctx context.Context) error {
	if s == nil || migrationContext(ctx) != nil {
		return errMigrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if migrationContext(ctx) != nil || s.state != migrationIdle {
		return errMigrationUnavailable
	}
	existing, err := s.journal.load(ctx)
	if err == nil && s.matching(existing) && existing.state == migrationUnknown {
		s.state = migrationUnknown
		return errMigrationUnknown
	}
	if err != nil || existing != nil {
		s.state = migrationBlocked
		return errMigrationUnavailable
	}
	if s.backend.verifyBeforePlacement(ctx, s.planCopy()) != nil || migrationContext(ctx) != nil {
		s.state = migrationBlocked
		return errMigrationUnavailable
	}
	// This barrier precedes canonical file placement, not only the later ACL call.
	s.state = migrationUnknown
	if s.journal.markUnknown(ctx, s.record()) != nil || migrationContext(ctx) != nil {
		return errMigrationUnknown
	}
	if s.backend.place(ctx, s.planCopy()) != nil || migrationContext(ctx) != nil {
		return errMigrationUnknown
	}
	// Successful placement does not resolve the transition or authorize runtime
	// start: explicit full verification must follow migration and configuration.
	return nil
}
func (s *migrationStageController) reconcile(ctx context.Context) error {
	if s == nil || migrationContext(ctx) != nil {
		return errMigrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if migrationContext(ctx) != nil {
		return errMigrationUnavailable
	}
	existing, err := s.journal.load(ctx)
	if err != nil || !s.matching(existing) {
		s.state = migrationBlocked
		return errMigrationUnavailable
	}
	s.state = migrationUnknown
	if s.backend.verifyComplete(ctx, s.planCopy()) != nil || migrationContext(ctx) != nil {
		return errMigrationUnknown
	}
	if existing.state == migrationUnknown && s.journal.markVerified(ctx, s.record()) != nil {
		return errMigrationUnknown
	}
	if migrationContext(ctx) != nil {
		return errMigrationUnknown
	}
	s.state = migrationVerified
	return nil
}
func (*migrationStageController) String() string   { return "Mechanize runtime staging" }
func (*migrationStageController) GoString() string { return "Mechanize runtime staging" }
func (*migrationStageController) MarshalJSON() ([]byte, error) {
	return []byte(`{"state":"private"}`), nil
}

func (p migrationStagePlan) configPath() string {
	if p.updateConfig != "" {
		return p.updateConfig
	}
	return filepath.Join(filepath.Dir(p.options.canonicalExecutable), "config.json")
}
