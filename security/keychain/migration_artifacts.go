//go:build darwin || linux

package keychain

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type migrationRuntimeArtifact struct {
	Role                           string `json:"role"`
	Target                         string `json:"target"`
	Candidate                      string `json:"candidate"`
	Old, New                       migrationRuntimeInventory
	OldDigest, NewDigest           string
	OldRequirement, NewRequirement string
}
type migrationRuntimeArtifactPlan struct {
	BrokerPath, OldBrokerRequirement, NewBrokerRequirement        string
	ActiveHelperPath, ActiveHelperRequirement, ActiveHelperSHA256 string
	ChromeExecutable, ExtensionID                                 string
	ExtensionStorageSHA256                                        string `json:"ExtensionStorageSHA256,omitempty"`
	OldConsoleBirth                                               string
	Artifacts                                                     []migrationRuntimeArtifact
	Mode                                                          string                            `json:"Mode,omitempty"`
	PreservedExtension                                            *migrationPreservedExtension      `json:"PreservedExtension,omitempty"`
	ChromeRequirement                                             string                            `json:"ChromeRequirement,omitempty"`
	ChromeRecovery                                                *migrationChromeRecovery          `json:"ChromeRecovery,omitempty"`
	NativeRecordRoot                                              string                            `json:"NativeRecordRoot,omitempty"`
	NewBrokerPath                                                 string                            `json:"NewBrokerPath,omitempty"`
	LegacyArtifacts                                               []migrationRuntimeArtifact        `json:"LegacyArtifacts,omitempty"`
	PreinstalledUnifiedApp                                        bool                              `json:"preinstalledUnifiedApp,omitempty"`
	PreinstalledApprovalConsole                                   bool                              `json:"preinstalledApprovalConsole,omitempty"`
	ApprovalConsole                                               *migrationApprovalConsole         `json:"ApprovalConsole,omitempty"`
	OriginalConsoleArtifact                                       *migrationOriginalConsoleArtifact `json:"OriginalConsoleArtifact,omitempty"`
	ConfigPath                                                    string                            `json:"ConfigPath,omitempty"`
}

// Metadata-only receipts from the actual Mechanize browser/native workflow.
// No profile database or credential storage is read by this component. The
// observer must independently verify receipt provenance; these private structs
// are not JSON/tool request types and cannot establish native-human authority.
type migrationRuntimeObservation struct {
	mode                                            string
	at                                              time.Time
	receiptSHA256                                   string
	stoppedExecutables                              []string
	loadedExtensionPath, extensionID, storageSHA256 string
	oldConsoleRequirement, oldConsoleBirth          string
}
type migrationRuntimeTerminalEvidence struct {
	receiptSHA256, newConsoleCredentialReceiptSHA256, newConsoleAccount string
}
type migrationRuntimeObserver interface {
	observe(context.Context) (migrationRuntimeObservation, error)
	terminal(context.Context) (migrationRuntimeTerminalEvidence, error)
}
type migrationRuntimeSignatureVerifier interface {
	verify(context.Context, string, string, string) error
}
type migrationRuntimeArtifacts struct {
	mu                                                           sync.Mutex
	plan                                                         migrationRuntimeArtifactPlan
	journal                                                      migrationJournal
	observer                                                     migrationRuntimeObserver
	signatures                                                   migrationRuntimeSignatureVerifier
	record                                                       *migrationJournalRecord
	attempted, nonConsolePlaced, consoleAttempted, consolePlaced bool
}

func (*migrationRuntimeArtifacts) String() string   { return "Checked runtime artifact placement" }
func (*migrationRuntimeArtifacts) GoString() string { return "Checked runtime artifact placement" }
func (*migrationRuntimeArtifacts) MarshalJSON() ([]byte, error) {
	return []byte(`{"state":"private"}`), nil
}
func runtimeRoleRequirement(role, requirement string) bool {
	suffix := map[string]string{"helper": "native", "native-host": "chrome.nativehost", "console": "consent"}[role]
	return suffix != "" && regexp.MustCompile(`^identifier "com\.viant\.mechanize\.`+regexp.QuoteMeta(suffix)+`" and cdhash H"[a-f0-9]{40}"$`).MatchString(requirement)
}
func newRuntimeArtifactsWith(plan migrationRuntimeArtifactPlan, journal migrationJournal, observer migrationRuntimeObserver, signatures migrationRuntimeSignatureVerifier) (*migrationRuntimeArtifacts, error) {
	if unifiedRuntimeMode(plan.Mode) {
		if journal == nil || observer == nil || signatures == nil || !validUnifiedRuntime(plan) || !validMigrationExtensionMode(plan) {
			return nil, errMigrationUnavailable
		}
		copied := plan
		if plan.ApprovalConsole != nil {
			a := *plan.ApprovalConsole
			copied.ApprovalConsole = &a
		}
		if plan.OriginalConsoleArtifact != nil {
			o := *plan.OriginalConsoleArtifact
			o.Inventory = runtimeInventoryCopy(o.Inventory)
			copied.OriginalConsoleArtifact = &o
		}
		copied.Artifacts = nil
		copied.LegacyArtifacts = nil
		clone := func(a migrationRuntimeArtifact) migrationRuntimeArtifact {
			a.Old = runtimeInventoryCopy(a.Old)
			a.New = runtimeInventoryCopy(a.New)
			return a
		}
		for _, a := range plan.Artifacts {
			copied.Artifacts = append(copied.Artifacts, clone(a))
		}
		for _, a := range plan.LegacyArtifacts {
			copied.LegacyArtifacts = append(copied.LegacyArtifacts, clone(a))
		}
		preserved := *plan.PreservedExtension
		preserved.Inventory = runtimeInventoryCopy(preserved.Inventory)
		copied.PreservedExtension = &preserved
		if plan.ChromeRecovery != nil {
			recovery := *plan.ChromeRecovery
			copied.ChromeRecovery = &recovery
		}
		return &migrationRuntimeArtifacts{plan: copied, journal: journal, observer: observer, signatures: signatures}, nil
	}

	if journal == nil || observer == nil || signatures == nil || !migrationPackagedPath(plan.BrokerPath) || !migrationRequirement.MatchString(plan.OldBrokerRequirement) || !migrationRequirement.MatchString(plan.NewBrokerRequirement) || plan.OldBrokerRequirement == plan.NewBrokerRequirement ||
		!migrationPackagedPath(plan.ActiveHelperPath) || !runtimeRoleRequirement("helper", plan.ActiveHelperRequirement) || !validMigrationID(plan.ActiveHelperSHA256) || !migrationPackagedPath(plan.ChromeExecutable) || plan.OldConsoleBirth == "" || len(plan.OldConsoleBirth) > 128 || strings.ContainsRune(plan.OldConsoleBirth, 0) || !regexp.MustCompile(`^[a-p]{32}$`).MatchString(plan.ExtensionID) || !validMigrationExtensionMode(plan) {
		return nil, errMigrationUnavailable
	}
	seen := map[string]bool{}
	paths := map[string]bool{plan.BrokerPath: true}
	copy := plan
	if plan.ChromeRecovery != nil {
		recovery := *plan.ChromeRecovery
		copy.ChromeRecovery = &recovery
	}
	copy.Artifacts = nil
	for _, a := range plan.Artifacts {
		if seen[a.Role] || !migrationPackagedPath(a.Target) || !migrationPackagedPath(a.Candidate) || a.Target == a.Candidate || paths[a.Target] || paths[a.Candidate] || !runtimeValidInventory(a.Old) || !runtimeValidInventory(a.New) || runtimeInventoryDigest(a.Old) != a.OldDigest || runtimeInventoryDigest(a.New) != a.NewDigest {
			return nil, errMigrationUnavailable
		}
		seen[a.Role] = true
		paths[a.Target] = true
		paths[a.Candidate] = true
		switch a.Role {
		case "helper", "native-host":
			expected := map[string]string{"helper": "mechanize-native", "native-host": "mechanize-native-host"}[a.Role]
			if filepath.Dir(a.Target) != filepath.Dir(plan.BrokerPath) || filepath.Base(a.Target) != expected || a.Old["."].Kind != "file" || a.New["."].Kind != "file" || a.New["."].Mode&0100 == 0 || !runtimeRoleRequirement(a.Role, a.OldRequirement) || !runtimeRoleRequirement(a.Role, a.NewRequirement) {
				return nil, errMigrationUnavailable
			}
		case "console":
			if filepath.Dir(a.Target) != filepath.Dir(plan.BrokerPath) || filepath.Base(a.Target) != "Mechanize Permissions.app" || a.Old["."].Kind != "directory" || a.New["."].Kind != "directory" || !runtimeRoleRequirement(a.Role, a.OldRequirement) || !runtimeRoleRequirement(a.Role, a.NewRequirement) {
				return nil, errMigrationUnavailable
			}
		case "extension":
			if plan.Mode != "" {
				return nil, errMigrationUnavailable
			}
			if _, e := runtimeExtensionContract(a.Old, true); e != nil {
				return nil, e
			}
			if _, e := runtimeExtensionContract(a.New, false); e != nil {
				return nil, e
			}
			if a.OldRequirement != "" || a.NewRequirement != "" {
				return nil, errMigrationUnavailable
			}
		default:
			return nil, errMigrationUnavailable
		}
		a.Old = runtimeInventoryCopy(a.Old)
		a.New = runtimeInventoryCopy(a.New)
		copy.Artifacts = append(copy.Artifacts, a)
	}
	if plan.Mode == preserveExtensionMode {
		preserved := *plan.PreservedExtension
		preserved.Inventory = runtimeInventoryCopy(preserved.Inventory)
		copy.PreservedExtension = &preserved
		for path := range paths {
			if migrationPathsOverlap(path, preserved.Path) {
				return nil, errMigrationUnavailable
			}
		}
	}
	// A directory artifact must never contain another selected artifact or a
	// candidate. In particular this cannot recursively sweep a runtime/config root.
	for path := range paths {
		for other := range paths {
			if path != other && strings.HasPrefix(other, path+string(filepath.Separator)) {
				return nil, errMigrationUnavailable
			}
		}
	}
	helper := migrationRuntimeArtifact{}
	for _, artifact := range copy.Artifacts {
		if artifact.Role == "helper" {
			helper = artifact
		}
	}
	if plan.ActiveHelperPath == helper.Target {
		if plan.ActiveHelperRequirement != helper.OldRequirement || plan.ActiveHelperSHA256 != helper.Old["."].SHA256 {
			return nil, errMigrationUnavailable
		}
	} else {
		for _, artifact := range copy.Artifacts {
			if plan.ActiveHelperPath == artifact.Target || strings.HasPrefix(plan.ActiveHelperPath, artifact.Target+string(filepath.Separator)) {
				return nil, errMigrationUnavailable
			}
		}
	}
	return &migrationRuntimeArtifacts{plan: copy, journal: journal, observer: observer, signatures: signatures}, nil
}
func (r *migrationRuntimeArtifacts) artifact(role string) migrationRuntimeArtifact {
	for _, a := range r.readOnlyArtifacts() {
		if a.Role == role {
			return a
		}
	}
	return migrationRuntimeArtifact{}
}
func (r *migrationRuntimeArtifacts) digest(p migrationStagePlan) string {
	data, _ := json.Marshal([]any{"mechanize-runtime-artifacts-v1", migrationStageDigest(p), r.plan})
	return migrationDigest(data)
}
func (r *migrationRuntimeArtifacts) binding(p migrationStagePlan) bool {
	if unifiedRuntimeMode(r.plan.Mode) && (len(r.plan.Artifacts) != 1 || (r.plan.Mode == unifiedAppMode && p.options.destinationExecutable() != r.plan.NewBrokerPath) || (r.plan.Mode == unifiedUpdateMode && (p.updateConfig == "" || p.updateOldInventorySHA256 != r.plan.Artifacts[0].OldDigest)) || p.unifiedInventorySHA256 != r.plan.Artifacts[0].NewDigest || p.preinstalledUnifiedApp != r.plan.PreinstalledUnifiedApp) {
		return false
	}

	return validMigrationStagePlan(p) && p.options.canonicalExecutable == r.plan.BrokerPath && p.options.oldRequirement == r.plan.OldBrokerRequirement && p.options.newRequirement == r.plan.NewBrokerRequirement
}
func (r *migrationRuntimeArtifacts) observe(ctx context.Context) error {
	if migrationContext(ctx) != nil {
		return errMigrationUnavailable
	}
	evidence, err := r.observer.observe(ctx)
	extensionPath := r.artifact("extension").Target
	if r.plan.Mode == preserveExtensionMode || unifiedRuntimeMode(r.plan.Mode) {
		extensionPath = r.plan.PreservedExtension.Path
	}
	if r.plan.ChromeRecovery != nil && r.signatures.verify(ctx, "chrome-recovery", r.plan.ChromeExecutable, r.plan.ChromeRequirement) != nil {
		return errMigrationUnavailable
	}
	if r.verifyPreservedExtension() != nil {
		return errMigrationUnavailable
	}
	console := r.artifact("console")
	if err != nil || !validMigrationID(evidence.receiptSHA256) || evidence.at.After(time.Now()) || time.Since(evidence.at) > 30*time.Second || evidence.mode != r.plan.Mode || evidence.loadedExtensionPath != extensionPath || evidence.extensionID != r.plan.ExtensionID || evidence.storageSHA256 != r.plan.ExtensionStorageSHA256 || evidence.oldConsoleRequirement != console.OldRequirement || evidence.oldConsoleBirth != r.plan.OldConsoleBirth || len(evidence.oldConsoleBirth) > 128 || strings.ContainsRune(evidence.oldConsoleBirth, 0) {
		return errMigrationUnavailable
	}
	stopped := map[string]bool{}
	for _, path := range evidence.stoppedExecutables {
		stopped[path] = true
	}
	for _, path := range []string{r.plan.BrokerPath, r.plan.ActiveHelperPath, r.artifact("helper").Target, r.artifact("native-host").Target, r.plan.ChromeExecutable} {
		if !stopped[path] {
			return errMigrationUnavailable
		}
	}
	return nil
}
func (r *migrationRuntimeArtifacts) verifyArtifact(ctx context.Context, a migrationRuntimeArtifact, path string, newVersion bool) error {
	inventory, requirement, broker := a.Old, a.OldRequirement, r.plan.OldBrokerRequirement
	helper := r.artifact("helper").OldRequirement
	if newVersion {
		inventory, requirement, broker = a.New, a.NewRequirement, r.plan.NewBrokerRequirement
		helper = r.artifact("helper").NewRequirement
	}
	if r.plan.PreinstalledApprovalConsole && a.Role == "console" && a.Target == r.plan.Artifacts[0].Candidate {
		broker = r.plan.NewBrokerRequirement
		helper = r.artifact("helper").NewRequirement
	}
	if runtimeVerifyInventory(path, inventory) != nil {
		return errMigrationUnavailable
	}
	if a.Role == "extension" {
		key, err := runtimeExtensionIdentity(path, inventory)
		if err != nil {
			return err
		}
		if key != "" {
			id, e := runtimeExtensionIDFromKey(key)
			if e != nil || id != r.plan.ExtensionID {
				return errMigrationUnavailable
			}
		}
		return nil
	}
	if r.signatures.verify(ctx, a.Role, path, requirement) != nil {
		return errMigrationUnavailable
	}
	switch a.Role {
	case "helper":
		pin, err := runtimeHelperBrokerPin(path, inventory)
		if err != nil || pin != broker {
			return errMigrationUnavailable
		}
	case "native-host":
		pin, err := runtimeHostBrokerPin(path, inventory)
		if err != nil || pin != broker {
			return errMigrationUnavailable
		}
	case "console":
		data, err := runtimeReadFile(filepath.Join(path, "Contents/Info.plist"), inventory["Contents/Info.plist"])
		if err != nil {
			return err
		}
		values, err := runtimePlistStrings(data)
		if err != nil || values["MechanizeBrokerRequirement"] != broker || values["MechanizeHelperRequirement"] != helper || values["MechanizeEnrollmentAccount"] == "" {
			return errMigrationUnavailable
		}
	}
	return runtimeVerifyInventory(path, inventory)
}
func (r *migrationRuntimeArtifacts) activeHelperUnchanged(ctx context.Context) error {
	// The config's actual active helper may be a private preflight path rather
	// than root/mechanize-native. It is separately stopped, pinned and preserved.
	if r.plan.ActiveHelperPath == r.artifact("helper").Target {
		return nil
	}
	inventory, err := runtimeInventory(r.plan.ActiveHelperPath)
	if err != nil || len(inventory) != 1 || inventory["."].SHA256 != r.plan.ActiveHelperSHA256 || r.signatures.verify(ctx, "helper", r.plan.ActiveHelperPath, r.plan.ActiveHelperRequirement) != nil {
		return errMigrationUnavailable
	}
	return nil
}
func (r *migrationRuntimeArtifacts) inspectPrepared(ctx context.Context, p migrationStagePlan) error {
	if !r.binding(p) {
		return errMigrationUnavailable
	}
	return r.prepared(ctx)
}

// The composition's pre-prepare gate has no item/transition yet. It still checks
// the entire frozen artifact set, actual browser qualification and active helper.
func (r *migrationRuntimeArtifacts) prepared(ctx context.Context) error {
	if r.verifyOriginalConsole(ctx) != nil {
		return errMigrationUnavailable
	}
	if r.observe(ctx) != nil || r.activeHelperUnchanged(ctx) != nil {
		return errMigrationUnavailable
	}
	for _, a := range r.readOnlyArtifacts() {
		if r.verifyArtifact(ctx, a, a.Target, false) != nil || r.verifyArtifact(ctx, a, a.Candidate, true) != nil {
			return errMigrationUnavailable
		}
	}
	if r.plan.Mode == unifiedUpdateMode {
		a := r.artifact("console")
		old, err := runtimeReadFile(filepath.Join(a.Target, "Contents/Info.plist"), a.Old["Contents/Info.plist"])
		if err != nil {
			return errMigrationUnavailable
		}
		next, err := runtimeReadFile(filepath.Join(a.Candidate, "Contents/Info.plist"), a.New["Contents/Info.plist"])
		if err != nil {
			return errMigrationUnavailable
		}
		before, e1 := runtimePlistStrings(old)
		after, e2 := runtimePlistStrings(next)
		if e1 != nil || e2 != nil || before["MechanizeEnrollmentAccount"] == "" || after["MechanizeEnrollmentAccount"] == "" || before["MechanizeEnrollmentAccount"] == after["MechanizeEnrollmentAccount"] {
			return errMigrationUnavailable
		}
	}
	if r.plan.Mode == preserveExtensionMode || unifiedRuntimeMode(r.plan.Mode) {
		return r.verifyPreservedExtension()
	}
	a := r.artifact("extension")
	old, e1 := runtimeExtensionIdentity(a.Target, a.Old)
	next, e2 := runtimeExtensionIdentity(a.Candidate, a.New)
	if e1 != nil || e2 != nil || old != next {
		return errMigrationUnavailable
	}
	return nil
}
func runtimeRetainedArtifact(a migrationRuntimeArtifact, transition string) string {
	return filepath.Join(filepath.Dir(a.Target), ".runtime-exchange-"+transition+"-"+a.Role)
}
func (r *migrationRuntimeArtifacts) exchange(ctx context.Context, a migrationRuntimeArtifact, p migrationStagePlan, check func() error) error {
	if check == nil || check() != nil || migrationContext(ctx) != nil || r.verifyArtifact(ctx, a, a.Target, false) != nil {
		return errMigrationUnavailable
	}
	dir, err := runtimeArtifactParent(a.Target)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	old, err := unix.Openat(dir, filepath.Base(a.Target), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return errMigrationUnavailable
	}
	defer unix.Close(old)
	retained := runtimeRetainedArtifact(a, p.transitionID)
	if runtimeCopyInventory(a.Candidate, retained, a.New) != nil || r.verifyArtifact(ctx, a, retained, true) != nil {
		return errMigrationUnknown
	}
	fresh, err := unix.Openat(dir, filepath.Base(retained), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return errMigrationUnknown
	}
	defer unix.Close(fresh)
	if runtimeEntryMatches(dir, filepath.Base(a.Target), old) != nil || runtimeEntryMatches(dir, filepath.Base(retained), fresh) != nil || runtimeParentMatches(a.Target, dir) != nil || check() != nil || r.observe(ctx) != nil || migrationContext(ctx) != nil {
		return errMigrationUnknown
	}
	if migrationExchangeNames(dir, filepath.Base(retained), filepath.Base(a.Target)) != nil {
		return errMigrationUnknown
	}
	if unix.Fsync(dir) != nil || runtimeEntryMatches(dir, filepath.Base(retained), old) != nil || runtimeEntryMatches(dir, filepath.Base(a.Target), fresh) != nil || runtimeParentMatches(a.Target, dir) != nil || check() != nil || r.verifyArtifact(ctx, a, a.Target, true) != nil || r.verifyArtifact(ctx, a, retained, false) != nil {
		return errMigrationUnknown
	}
	return nil
}
func (r *migrationRuntimeArtifacts) placeNonConsole(ctx context.Context, p migrationStagePlan, check func() error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.attempted || check == nil || check() != nil || r.inspectPrepared(ctx, p) != nil {
		return errMigrationUnavailable
	}
	r.attempted = true
	previous, err := r.journal.load(ctx)
	if err != nil || previous != nil {
		return errMigrationUnavailable
	}
	record := migrationJournalRecord{state: migrationUnknown, transitionID: p.transitionID, optionsSHA256: r.digest(p), identity: bytes.Clone(p.itemIdentity)}
	r.record = &record
	if r.journal.markUnknown(ctx, record) != nil {
		return errMigrationUnknown
	}
	for _, role := range r.nonConsoleRoles() {
		if r.exchange(ctx, r.artifact(role), p, check) != nil {
			return errMigrationUnknown
		}
	}
	if r.verifyNonConsoleReady(ctx, p) != nil {
		return errMigrationUnknown
	}
	r.nonConsolePlaced = true
	return nil
}
func (r *migrationRuntimeArtifacts) matchingRecord(ctx context.Context, p migrationStagePlan) error {
	actual, err := r.journal.load(ctx)
	if err != nil || actual == nil || actual.transitionID != p.transitionID || actual.optionsSHA256 != r.digest(p) || !bytes.Equal(actual.identity, p.itemIdentity) || (actual.state != migrationUnknown && actual.state != migrationVerified) {
		return errMigrationUnavailable
	}
	return nil
}

// This is deliberately not full readiness: old console remains canonical and
// the artifact journal stays unknown until explicit terminal publication.
func (r *migrationRuntimeArtifacts) verifyNonConsoleReady(ctx context.Context, p migrationStagePlan) error {
	if !r.binding(p) || r.matchingRecord(ctx, p) != nil || r.observe(ctx) != nil || r.activeHelperUnchanged(ctx) != nil || r.verifyPreservedExtension() != nil {
		return errMigrationUnavailable
	}
	for _, role := range r.nonConsoleRoles() {
		a := r.artifact(role)
		if r.verifyArtifact(ctx, a, a.Target, true) != nil || r.verifyArtifact(ctx, a, runtimeRetainedArtifact(a, p.transitionID), false) != nil {
			return errMigrationUnavailable
		}
	}
	a := r.artifact("console")
	return r.verifyArtifact(ctx, a, a.Target, false)
}
func (r *migrationRuntimeArtifacts) placeConsoleTerminal(ctx context.Context, p migrationStagePlan, receipt migrationCompositionReceipt, check func() error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if receipt.State != migrationVerified || receipt.Scope != "custody-broker-config" || receipt.TransitionID != p.transitionID || r.consoleAttempted || check == nil || check() != nil || !r.nonConsolePlaced || r.verifyNonConsoleReady(ctx, p) != nil {
		return errMigrationUnavailable
	}
	// Only the local composition can supply custody completion. The observer
	// supplies independent credential readiness, never a worker-success claim.
	proof, err := r.observer.terminal(ctx)
	a := r.artifact("console")
	data, e := runtimeReadFile(filepath.Join(a.Candidate, "Contents/Info.plist"), a.New["Contents/Info.plist"])
	values, e2 := runtimePlistStrings(data)
	if err != nil || e != nil || e2 != nil || receipt.State != migrationVerified || receipt.Scope != "custody-broker-config" || receipt.TransitionID != p.transitionID || !validMigrationID(proof.receiptSHA256) || !validMigrationID(proof.newConsoleCredentialReceiptSHA256) || proof.newConsoleAccount != values["MechanizeEnrollmentAccount"] {
		return errMigrationUnavailable
	}
	r.consoleAttempted = true
	if r.exchange(ctx, a, p, check) != nil {
		return errMigrationUnknown
	}
	r.consolePlaced = true
	if r.verifyCompleteLocked(ctx, p, check) != nil {
		return errMigrationUnknown
	}
	return nil
}
func (r *migrationRuntimeArtifacts) verifyComplete(ctx context.Context, p migrationStagePlan, check func() error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.verifyCompleteLocked(ctx, p, check)
}
func (r *migrationRuntimeArtifacts) verifyCompleteLocked(ctx context.Context, p migrationStagePlan, check func() error) error {
	if check == nil || check() != nil {
		return errMigrationUnavailable
	}
	if !r.binding(p) || r.matchingRecord(ctx, p) != nil || r.observe(ctx) != nil || r.activeHelperUnchanged(ctx) != nil || r.verifyPreservedExtension() != nil {
		return errMigrationUnavailable
	}
	for _, a := range r.plan.Artifacts {
		if r.verifyArtifact(ctx, a, a.Target, true) != nil || r.verifyArtifact(ctx, a, runtimeRetainedArtifact(a, p.transitionID), false) != nil {
			return errMigrationUnavailable
		}
	}
	// File readiness alone cannot clear the runtime journal. The terminal phase
	// requires the worker receipt and new-console credential readiness above.
	if !r.consolePlaced {
		return errMigrationUnknown
	}
	record := migrationJournalRecord{state: migrationUnknown, transitionID: p.transitionID, optionsSHA256: r.digest(p), identity: bytes.Clone(p.itemIdentity)}
	existing, err := r.journal.load(ctx)
	if err != nil {
		return errMigrationUnknown
	}
	if check() != nil {
		return errMigrationUnknown
	}
	if existing.state == migrationUnknown && r.journal.markVerified(ctx, record) != nil {
		return errMigrationUnknown
	}
	return nil
}
func (r *migrationRuntimeArtifacts) requiredQuiescencePaths() []string {
	v := []string{r.plan.BrokerPath, r.plan.ActiveHelperPath, r.artifact("helper").Target, r.artifact("native-host").Target, r.plan.ChromeExecutable}
	sort.Strings(v)
	return v
}

// Wrap the composition's checked broker/config stage factory. This performs real
// additional placement after the base file placement and before any ACL commit.
// The existing staging journal protects the whole call; this component also
// maintains its distinct full-artifact journal and retained displaced trees.
func (r *migrationRuntimeArtifacts) stageFactory(base migrationInstallStageFactory) migrationInstallStageFactory {
	if base == nil {
		return nil
	}
	return func(ctx context.Context, p migrationStagePlan, check func() error) (*migrationStageController, error) {
		if check == nil || !r.binding(p) {
			return nil, errMigrationUnavailable
		}
		stage, err := base(ctx, p, check)
		if err != nil || stage == nil {
			return nil, errMigrationUnavailable
		}
		stage.backend = &migrationRuntimeStageBackend{base: stage.backend, artifacts: r, check: check}
		return stage, nil
	}
}

type migrationRuntimeStageBackend struct {
	base      migrationStageBackend
	artifacts *migrationRuntimeArtifacts
	check     func() error
}

func (b *migrationRuntimeStageBackend) verifyBeforePlacement(ctx context.Context, p migrationStagePlan) error {
	if b.check() == nil && b.base.verifyBeforePlacement(ctx, p) == nil && b.artifacts.inspectPrepared(ctx, p) == nil {
		return nil
	}
	return errMigrationUnavailable
}
func (b *migrationRuntimeStageBackend) place(ctx context.Context, p migrationStagePlan) error {
	if b.check() != nil {
		return errMigrationUnavailable
	}
	if b.base.place(ctx, p) != nil || b.check() != nil || b.artifacts.placeNonConsole(ctx, p, b.check) != nil {
		return errMigrationUnknown
	}
	return nil
}
func (b *migrationRuntimeStageBackend) verifyComplete(ctx context.Context, p migrationStagePlan) error {
	if b.check() != nil || b.base.verifyComplete(ctx, p) != nil || b.artifacts.verifyNonConsoleReady(ctx, p) != nil || b.check() != nil {
		return errMigrationUnavailable
	}
	return nil
}

func (r *migrationRuntimeArtifacts) readOnlyArtifacts() []migrationRuntimeArtifact {
	if unifiedRuntimeMode(r.plan.Mode) {
		return r.plan.LegacyArtifacts
	}
	return r.plan.Artifacts
}
