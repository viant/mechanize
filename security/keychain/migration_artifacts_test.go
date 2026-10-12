//go:build darwin || linux

package keychain

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type runtimeObserverFixture struct {
	observation migrationRuntimeObservation
	proof       migrationRuntimeTerminalEvidence
	reject      bool
}

func (o *runtimeObserverFixture) observe(context.Context) (migrationRuntimeObservation, error) {
	if o.reject {
		return migrationRuntimeObservation{}, errMigrationUnavailable
	}
	copy := o.observation
	if copy.at.IsZero() {
		copy.at = time.Now()
	}
	copy.stoppedExecutables = append([]string(nil), copy.stoppedExecutables...)
	return copy, nil
}
func (o *runtimeObserverFixture) terminal(context.Context) (migrationRuntimeTerminalEvidence, error) {
	return o.proof, nil
}

type runtimeSignatureFixture struct {
	rejectRole string
	when       func() bool
	calls      int
}

func (s *runtimeSignatureFixture) verify(ctx context.Context, role, path, requirement string) error {
	s.calls++
	if migrationContext(ctx) != nil || !runtimeRoleRequirement(role, requirement) {
		return errMigrationUnavailable
	}
	if role == s.rejectRole && (s.when == nil || s.when()) {
		return errMigrationUnavailable
	}
	return nil
}
func runtimeFixtureRequirement(role, letter string) string {
	return fmt.Sprintf(`identifier "com.viant.mechanize.%s" and cdhash H"%s"`, role, strings.Repeat(letter, 40))
}
func runtimeFixturePlist(values map[string]string) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><plist version="1.0"><dict>`)
	for _, key := range []string{"MechanizeBrokerRequirement", "MechanizeHelperRequirement", "MechanizeEnrollmentAccount"} {
		if value, ok := values[key]; ok {
			b.WriteString("<key>" + key + "</key><string>" + value + "</string>")
		}
	}
	b.WriteString("</dict></plist>")
	return []byte(b.String())
}

// A synthetic little-endian Mach-O containing the exact signed-metadata section;
// platform signature verification remains an explicit fixture seam, never native.
func runtimeFixtureMachO(pin string) []byte {
	data := runtimeFixturePlist(map[string]string{"MechanizeBrokerRequirement": pin})
	result := make([]byte, 184+len(data))
	put := func(offset int, value uint32) { binary.LittleEndian.PutUint32(result[offset:], value) }
	put(0, 0xfeedfacf)
	put(4, 0x0100000c)
	put(12, 2)
	put(16, 1)
	put(20, 152)
	put(32, 0x19)
	put(36, 152)
	copy(result[40:], "__TEXT")
	binary.LittleEndian.PutUint64(result[64:], uint64(len(result)))
	binary.LittleEndian.PutUint64(result[80:], uint64(len(result)))
	put(96, 1)
	copy(result[104:], "__info_plist")
	copy(result[120:], "__TEXT")
	binary.LittleEndian.PutUint64(result[144:], uint64(len(data)))
	put(152, 184)
	copy(result[184:], data)
	return result
}
func runtimeWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}
func runtimeExtensionFixture(t *testing.T, path, version string) {
	t.Helper()
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range runtimeExtensionFiles {
		data := []byte(version + ":" + name)
		if name == "manifest.json" {
			data = []byte(`{"manifest_version":3,"name":"Fixture","version":"` + version + `","background":{"service_worker":"worker.js","type":"module"},"options_page":"options.html"}`)
		}
		runtimeWrite(t, filepath.Join(path, name), data, 0600)
	}
}
func runtimeConsoleFixture(t *testing.T, path, broker, helper, account string) {
	t.Helper()
	runtimeWrite(t, filepath.Join(path, "Contents", "Info.plist"), runtimeFixturePlist(map[string]string{"MechanizeBrokerRequirement": broker, "MechanizeHelperRequirement": helper, "MechanizeEnrollmentAccount": account}), 0600)
	runtimeWrite(t, filepath.Join(path, "Contents", "MacOS", "MechanizeConsent"), []byte("synthetic-console-"+account), 0700)
}

type runtimePlacementFixture struct {
	r          *migrationRuntimeArtifacts
	p          migrationStagePlan
	observer   *runtimeObserverFixture
	signatures *runtimeSignatureFixture
	journal    *fileMigrationJournal
	ctx        context.Context
	check      func() error
	release    func()
	protected  string
}

func newRuntimePlacementFixture(t *testing.T) *runtimePlacementFixture {
	t.Helper()
	root := migrationFilesRoot(t)
	installed := filepath.Join(root, "runtime")
	candidate := filepath.Join(root, "candidate")
	if err := os.Mkdir(installed, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(candidate, 0700); err != nil {
		t.Fatal(err)
	}
	p := stageFixturePlan()
	p.options.canonicalExecutable = filepath.Join(installed, "mechanize")
	runtimeWrite(t, p.options.canonicalExecutable, []byte("original-broker-untouched"), 0700)
	helperOld, helperNew := runtimeFixtureRequirement("native", "1"), runtimeFixtureRequirement("native", "2")
	hostOld, hostNew := runtimeFixtureRequirement("chrome.nativehost", "3"), runtimeFixtureRequirement("chrome.nativehost", "4")
	consoleOld, consoleNew := runtimeFixtureRequirement("consent", "5"), runtimeFixtureRequirement("consent", "6")
	runtimeWrite(t, filepath.Join(installed, "mechanize-native"), runtimeFixtureMachO(p.options.oldRequirement), 0700)
	runtimeWrite(t, filepath.Join(candidate, "mechanize-native"), runtimeFixtureMachO(p.options.newRequirement), 0700)
	runtimeWrite(t, filepath.Join(installed, "mechanize-native-host"), []byte("host "+p.options.oldRequirement), 0700)
	runtimeWrite(t, filepath.Join(candidate, "mechanize-native-host"), []byte("host "+p.options.newRequirement), 0700)
	runtimeConsoleFixture(t, filepath.Join(installed, "Mechanize Permissions.app"), p.options.oldRequirement, helperOld, "existing-account")
	runtimeConsoleFixture(t, filepath.Join(candidate, "Mechanize Permissions.app"), p.options.newRequirement, helperNew, "new-account")
	// The actual loaded extension deliberately lives outside runtime/extension.
	loaded := filepath.Join(root, "actual-loaded-extension")
	runtimeExtensionFixture(t, loaded, "1")
	runtimeExtensionFixture(t, filepath.Join(candidate, "extension"), "2")
	active := filepath.Join(root, "helper-preflight", "mechanize-native")
	runtimeWrite(t, active, runtimeFixtureMachO(p.options.oldRequirement), 0700)
	plan := migrationRuntimeArtifactPlan{BrokerPath: p.options.canonicalExecutable, OldBrokerRequirement: p.options.oldRequirement, NewBrokerRequirement: p.options.newRequirement, ActiveHelperPath: active, ActiveHelperRequirement: runtimeFixtureRequirement("native", "7"), ChromeExecutable: filepath.Join(root, "Chrome"), ExtensionID: strings.Repeat("a", 32), ExtensionStorageSHA256: strings.Repeat("b", 64), OldConsoleBirth: "synthetic-process-generation"}
	activeInventory, err := runtimeInventory(active)
	if err != nil {
		t.Fatal(err)
	}
	plan.ActiveHelperSHA256 = activeInventory["."].SHA256
	for _, a := range []migrationRuntimeArtifact{{Role: "helper", Target: filepath.Join(installed, "mechanize-native"), Candidate: filepath.Join(candidate, "mechanize-native"), OldRequirement: helperOld, NewRequirement: helperNew}, {Role: "native-host", Target: filepath.Join(installed, "mechanize-native-host"), Candidate: filepath.Join(candidate, "mechanize-native-host"), OldRequirement: hostOld, NewRequirement: hostNew}, {Role: "console", Target: filepath.Join(installed, "Mechanize Permissions.app"), Candidate: filepath.Join(candidate, "Mechanize Permissions.app"), OldRequirement: consoleOld, NewRequirement: consoleNew}, {Role: "extension", Target: loaded, Candidate: filepath.Join(candidate, "extension")}} {
		a.Old, err = runtimeInventory(a.Target)
		if err != nil {
			t.Fatal(err)
		}
		a.New, err = runtimeInventory(a.Candidate)
		if err != nil {
			t.Fatal(err)
		}
		a.OldDigest = runtimeInventoryDigest(a.Old)
		a.NewDigest = runtimeInventoryDigest(a.New)
		plan.Artifacts = append(plan.Artifacts, a)
	}
	observer := &runtimeObserverFixture{observation: migrationRuntimeObservation{receiptSHA256: strings.Repeat("c", 64), loadedExtensionPath: loaded, extensionID: plan.ExtensionID, storageSHA256: plan.ExtensionStorageSHA256, oldConsoleRequirement: consoleOld, oldConsoleBirth: "synthetic-process-generation"}, proof: migrationRuntimeTerminalEvidence{receiptSHA256: strings.Repeat("d", 64), newConsoleCredentialReceiptSHA256: strings.Repeat("e", 64), newConsoleAccount: "new-account"}}
	signatures := &runtimeSignatureFixture{}
	journal, err := newPrivateMigrationJournal(filepath.Join(root, ".secret", "mechanize-runtime-artifacts"), "mechanize-runtime-artifacts")
	if err != nil {
		t.Fatal(err)
	}
	r, err := newRuntimeArtifactsWith(plan, journal, observer, signatures)
	if err != nil {
		t.Fatal(err)
	}
	observer.observation.stoppedExecutables = r.requiredQuiescencePaths()
	check, release, err := migrationPlacementLock(plan.BrokerPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	protected := filepath.Join(installed, "config-and-credential-reference.json")
	runtimeWrite(t, protected, []byte("synthetic-unchanged-configuration-and-enrollment-reference"), 0600)
	return &runtimePlacementFixture{r, p, observer, signatures, journal, migrationFixtureContext(t, true), check, release, protected}
}
func TestRuntimeArtifactsPlaceActualLoadedExtensionAndDeferConsole(t *testing.T) {
	f := newRuntimePlacementFixture(t)
	if err := f.r.inspectPrepared(f.ctx, f.p); err != nil {
		t.Fatal("prepare", err)
	}
	if err := f.r.placeNonConsole(f.ctx, f.p, f.check); err != nil {
		t.Fatal("placement", err)
	}
	console := f.r.artifact("console")
	if runtimeVerifyInventory(console.Target, console.Old) != nil {
		t.Fatal("old console peer bundle replaced before terminal")
	}
	record, _ := f.journal.load(f.ctx)
	if record.state != migrationUnknown {
		t.Fatal("staged console falsely cleared runtime journal")
	}
	if f.r.verifyComplete(f.ctx, f.p, f.check) == nil {
		t.Fatal("non-console phase claimed full readiness")
	}
	if err := f.r.placeConsoleTerminal(f.ctx, f.p, f.localReceipt(), f.check); err != nil {
		t.Fatal("terminal", err)
	}
	record, _ = f.journal.load(f.ctx)
	if record.state != migrationVerified {
		t.Fatal("complete runtime journal missing")
	}
	for _, a := range f.r.plan.Artifacts {
		if runtimeVerifyInventory(a.Target, a.New) != nil || runtimeVerifyInventory(runtimeRetainedArtifact(a, f.p.transitionID), a.Old) != nil {
			t.Fatal("lost new or displaced inventory", a.Role)
		}
	}
	if migrationReadFixture(t, f.protected) != "synthetic-unchanged-configuration-and-enrollment-reference" || migrationReadFixture(t, f.r.plan.BrokerPath) != "original-broker-untouched" {
		t.Fatal("unrelated configuration/broker changed")
	}
	if err := f.r.activeHelperUnchanged(f.ctx); err != nil {
		t.Fatal("active preflight helper changed")
	}
	if f.r.placeNonConsole(f.ctx, f.p, f.check) == nil || f.r.placeConsoleTerminal(f.ctx, f.p, f.localReceipt(), f.check) == nil {
		t.Fatal("runtime placement replayed")
	}
}
func TestRuntimeArtifactsRequireFreshActualPathIDStorageAndActiveHelperQuiescence(t *testing.T) {
	for _, mode := range []string{"canonical-guess", "id", "storage", "stale", "active-helper", "old-console", "console-birth"} {
		t.Run(mode, func(t *testing.T) {
			f := newRuntimePlacementFixture(t)
			switch mode {
			case "canonical-guess":
				f.observer.observation.loadedExtensionPath = filepath.Join(filepath.Dir(f.r.plan.BrokerPath), "extension", "chrome")
			case "id":
				f.observer.observation.extensionID = strings.Repeat("b", 32)
			case "storage":
				f.observer.observation.storageSHA256 = strings.Repeat("d", 64)
			case "stale":
				f.observer.observation.at = time.Now().Add(-time.Minute)
			case "active-helper":
				var paths []string
				for _, p := range f.observer.observation.stoppedExecutables {
					if p != f.r.plan.ActiveHelperPath {
						paths = append(paths, p)
					}
				}
				f.observer.observation.stoppedExecutables = paths
			case "console-birth":
				f.observer.observation.oldConsoleBirth = "replacement-process-generation"
			case "old-console":
				f.observer.observation.oldConsoleRequirement = f.r.artifact("console").NewRequirement
			}
			if f.r.placeNonConsole(f.ctx, f.p, f.check) == nil {
				t.Fatal("unqualified native/browser observation admitted")
			}
			if record, _ := f.journal.load(f.ctx); record != nil {
				t.Fatal("refused placement wrote journal")
			}
			for _, a := range f.r.plan.Artifacts {
				if runtimeVerifyInventory(a.Target, a.Old) != nil {
					t.Fatal("refused qualification changed files")
				}
			}
		})
	}
}
func TestRuntimeArtifactsPartialFailureRetainsUnknownAndBothVersions(t *testing.T) {
	f := newRuntimePlacementFixture(t)
	helper := f.r.artifact("helper")
	f.signatures.rejectRole = "native-host"
	f.signatures.when = func() bool { return runtimeVerifyInventory(helper.Target, helper.New) == nil }
	if err := f.r.placeNonConsole(f.ctx, f.p, f.check); err != errMigrationUnknown {
		t.Fatal(err)
	}
	record, _ := f.journal.load(f.ctx)
	if record == nil || record.state != migrationUnknown {
		t.Fatal("partial placement lost unknown barrier")
	}
	if runtimeVerifyInventory(helper.Target, helper.New) != nil || runtimeVerifyInventory(runtimeRetainedArtifact(helper, f.p.transitionID), helper.Old) != nil {
		t.Fatal("partial helper placement discarded versions")
	}
	if a := f.r.artifact("console"); runtimeVerifyInventory(a.Target, a.Old) != nil {
		t.Fatal("partial placement changed running console bundle")
	}
	if f.r.placeNonConsole(f.ctx, f.p, f.check) == nil {
		t.Fatal("partial placement replayed")
	}
}

// This receipt represents the local composition's result, separately from the
// observer's console-readiness metadata. It is not supplied by a protocol peer.
func (f *runtimePlacementFixture) localReceipt() migrationCompositionReceipt {
	return migrationCompositionReceipt{State: migrationVerified, Scope: "custody-broker-config", TransitionID: f.p.transitionID}
}

func TestRuntimeArtifactsTerminalRequiresWorkerAndCredentialReadiness(t *testing.T) {
	for _, mode := range []string{"worker", "transition", "credential", "account"} {
		t.Run(mode, func(t *testing.T) {
			f := newRuntimePlacementFixture(t)
			if err := f.r.placeNonConsole(f.ctx, f.p, f.check); err != nil {
				t.Fatal(err)
			}
			receipt := f.localReceipt()
			switch mode {
			case "worker":
				receipt.State = migrationUnknown
			case "transition":
				receipt.TransitionID = strings.Repeat("f", 64)
			case "credential":
				f.observer.proof.newConsoleCredentialReceiptSHA256 = ""
			case "account":
				f.observer.proof.newConsoleAccount = "unrelated-account"
			}
			if f.r.placeConsoleTerminal(f.ctx, f.p, receipt, f.check) == nil {
				t.Fatal("unverified terminal stage admitted")
			}
			a := f.r.artifact("console")
			if runtimeVerifyInventory(a.Target, a.Old) != nil {
				t.Fatal("terminal refusal replaced old console")
			}
		})
	}
}
func TestRuntimeInventoryRejectsSymlinksHardlinksAndUnlistedFiles(t *testing.T) {
	root := migrationFilesRoot(t)
	path := filepath.Join(root, "tree")
	runtimeExtensionFixture(t, path, "1")
	original, err := runtimeInventory(path)
	if err != nil {
		t.Fatal(err)
	}
	runtimeWrite(t, filepath.Join(path, "unlisted"), []byte("unexpected"), 0600)
	if runtimeVerifyInventory(path, original) == nil {
		t.Fatal("unlisted resource admitted")
	}
	os.Remove(filepath.Join(path, "unlisted"))
	if err = os.Symlink("worker.js", filepath.Join(path, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err = runtimeInventory(path); err == nil {
		t.Fatal("symlink admitted")
	}
	os.Remove(filepath.Join(path, "link"))
	if err = os.Link(filepath.Join(path, "worker.js"), filepath.Join(path, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, err = runtimeInventory(path); err == nil {
		t.Fatal("hardlink admitted")
	}
}
func TestRuntimeExtensionContractMatchesExistingPythonPackager(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	root := migrationFilesRoot(t)
	path := filepath.Join(root, "extension")
	runtimeExtensionFixture(t, path, "1")
	inventory, err := runtimeInventory(path)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := runtimeExtensionContract(inventory, false)
	if err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs("../../scripts/extension_package.py")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("python3", "-c", `import importlib.util,json,sys; s=importlib.util.spec_from_file_location('p',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m); print(json.dumps(m.inventory(sys.argv[2])))`, script, path)
	data, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	var actual struct {
		SHA256 string `json:"sha256"`
	}
	if json.Unmarshal(data, &actual) != nil || actual.SHA256 != digest {
		t.Fatal("Go/Python extension inventory contract drift")
	}
	// Current expected root mode is deliberately outside the extension-files hash,
	// matching Python's exact resource inventory contract.
	if !bytes.Equal([]byte(actual.SHA256), []byte(digest)) {
		t.Fatal("digest differs")
	}
}

func TestRuntimeArtifactStageFactoryJoinsRealBrokerConfigPlacement(t *testing.T) {
	f := newRuntimePlacementFixture(t)
	root := filepath.Dir(f.r.plan.BrokerPath)
	brokerCandidate := filepath.Join(filepath.Dir(f.r.artifact("helper").Candidate), "mechanize")
	runtimeWrite(t, brokerCandidate, []byte("new-broker"), 0700)
	config := filepath.Join(root, "config.json")
	configCandidate := filepath.Join(filepath.Dir(brokerCandidate), "config.json")
	runtimeWrite(t, config, []byte("old-config"), 0600)
	runtimeWrite(t, configCandidate, []byte("new-config"), 0600)
	f.p.oldBinarySHA256 = migrationDigest([]byte("original-broker-untouched"))
	f.p.newBinarySHA256 = migrationDigest([]byte("new-broker"))
	f.p.oldConfigSHA256 = migrationDigest([]byte("old-config"))
	f.p.newConfigSHA256 = migrationDigest([]byte("new-config"))
	stageJournal, err := newRuntimeStageJournal(filepath.Join(filepath.Dir(f.journal.root), "mechanize-runtime-staging"))
	if err != nil {
		t.Fatal(err)
	}
	base := func(ctx context.Context, p migrationStagePlan, check func() error) (*migrationStageController, error) {
		files, e := newMigrationFileStage(p, brokerCandidate, configCandidate, config, filepath.Join(root, "broker-backup"), func(context.Context) error { return nil }, func(context.Context, string, string) error { return nil }, func(context.Context, migrationStagePlan) error { return nil }, check)
		if e != nil {
			return nil, e
		}
		return newMigrationStageController(p, stageJournal, files)
	}
	factory := f.r.stageFactory(base)
	stage, err := factory(f.ctx, f.p, f.check)
	if err != nil {
		t.Fatal(err)
	}
	if err = stage.stage(f.ctx); err != nil {
		t.Fatal(err)
	}
	if migrationReadFixture(t, f.r.plan.BrokerPath) != "new-broker" || migrationReadFixture(t, config) != "new-config" {
		t.Fatal("base file placement was not joined")
	}
	if err = stage.reconcile(f.ctx); err != nil {
		t.Fatal(err)
	}
	record, _ := f.journal.load(f.ctx)
	if record.state != migrationUnknown {
		t.Fatal("scoped base readiness incorrectly completed deferred console")
	}
	if err = f.r.placeConsoleTerminal(f.ctx, f.p, f.localReceipt(), f.check); err != nil {
		t.Fatal(err)
	}
	if record, _ = f.journal.load(f.ctx); record.state != migrationVerified {
		t.Fatal("terminal phase did not complete artifact journal")
	}
}
func TestRuntimeArtifactsRejectFrozenButWrongReversePin(t *testing.T) {
	f := newRuntimePlacementFixture(t)
	for i, a := range f.r.plan.Artifacts {
		if a.Role == "helper" {
			runtimeWrite(t, a.Candidate, runtimeFixtureMachO(f.r.plan.OldBrokerRequirement), 0700)
			changed, err := runtimeInventory(a.Candidate)
			if err != nil {
				t.Fatal(err)
			}
			f.r.plan.Artifacts[i].New = changed
			f.r.plan.Artifacts[i].NewDigest = runtimeInventoryDigest(changed)
		}
	}
	if err := f.r.placeNonConsole(f.ctx, f.p, f.check); err == nil {
		t.Fatal("new helper pinned to old broker admitted")
	}
	if record, _ := f.journal.load(f.ctx); record != nil {
		t.Fatal("bad reverse pin wrote placement barrier")
	}
}
func TestRuntimeExtensionLegacyIsOldOnlyAndInventoryPathsAreBounded(t *testing.T) {
	root := migrationFilesRoot(t)
	path := filepath.Join(root, "extension")
	runtimeExtensionFixture(t, path, "1")
	for _, file := range []string{"connection-lifecycle.js", "focused-location.js", "tab-metadata.js", "control-badge-metadata.js", "protection-scopes.js", "accessibility-provider.js", "browser-input.js", "cdp-transport.js", "controller.js", "retirement.js", "fingerprint.js", "secure-input.js", "setup-metadata.js", "playwright-relay.js", "playwright-target.js", "playwright-worker.js"} {
		if err := os.Remove(filepath.Join(path, file)); err != nil {
			t.Fatal(err)
		}
	}
	legacy, err := runtimeInventory(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runtimeExtensionContract(legacy, true); err != nil {
		t.Fatal("qualified historical file set refused", err)
	}
	if _, err = runtimeExtensionContract(legacy, false); err == nil {
		t.Fatal("legacy set accepted as new package")
	}
	hostile := runtimeInventoryCopy(legacy)
	hostile["../credential"] = hostile["worker.js"]
	if runtimeValidInventory(hostile) {
		t.Fatal("inventory traversal admitted")
	}
}

func TestRuntimeExtensionPlaywrightRequiresCompleteNewPackage(t *testing.T) {
	root := migrationFilesRoot(t)
	path := filepath.Join(root, "extension")
	runtimeExtensionFixture(t, path, "29")
	current, err := runtimeInventory(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runtimeExtensionContract(current, false); err != nil {
		t.Fatal(err)
	}
	withoutProvider := runtimeInventoryCopy(current)
	delete(withoutProvider, "accessibility-provider.js")
	if _, err = runtimeExtensionContract(withoutProvider, true); err != nil {
		t.Fatal("installed pre-accessibility package rejected", err)
	}
	if _, err = runtimeExtensionContract(withoutProvider, false); err == nil {
		t.Fatal("package without accessible-name provider accepted as new")
	}
	missingLifecycle := runtimeInventoryCopy(current)
	delete(missingLifecycle, "connection-lifecycle.js")
	for _, old := range []bool{false, true} {
		if _, err = runtimeExtensionContract(missingLifecycle, old); err == nil {
			t.Fatal("partial lifecycle package accepted")
		}
	}
	partial := runtimeInventoryCopy(current)
	delete(partial, "playwright-target.js")
	for _, old := range []bool{false, true} {
		if _, err = runtimeExtensionContract(partial, old); err == nil {
			t.Fatal("incomplete Playwright package admitted")
		}
	}
	previous := runtimeInventoryCopy(current)
	for _, name := range []string{"connection-lifecycle.js", "focused-location.js", "tab-metadata.js", "control-badge-metadata.js", "protection-scopes.js", "accessibility-provider.js", "playwright-relay.js", "playwright-target.js", "playwright-worker.js"} {
		delete(previous, name)
	}
	if _, err = runtimeExtensionContract(previous, true); err != nil {
		t.Fatal("installed pre-Playwright package rejected", err)
	}
	if _, err = runtimeExtensionContract(previous, false); err == nil {
		t.Fatal("pre-Playwright package admitted as upgrade")
	}
}

func TestRuntimeArtifactExchangeRetainsConcurrentDirectoryEdit(t *testing.T) {
	f := newRuntimePlacementFixture(t)
	artifact := f.r.artifact("extension")
	calls := 0
	racing := func() error {
		calls++
		if err := f.check(); err != nil {
			return err
		}
		if calls == 2 {
			runtimeWrite(t, filepath.Join(artifact.Target, "worker.js"), []byte("concurrent-owner-edit"), 0600)
		}
		return nil
	}
	// Isolated publication primitive; the full placeNonConsole tests establish its
	// surrounding durable journal ordering. No application/profile data is involved.
	if err := f.r.exchange(f.ctx, artifact, f.p, racing); err != errMigrationUnknown {
		t.Fatal("changed displaced tree was accepted", err)
	}
	retained := runtimeRetainedArtifact(artifact, f.p.transitionID)
	if migrationReadFixture(t, filepath.Join(retained, "worker.js")) != "concurrent-owner-edit" {
		t.Fatal("concurrent edit was lost")
	}
	if runtimeVerifyInventory(artifact.Target, artifact.New) != nil || runtimeVerifyInventory(artifact.Candidate, artifact.New) != nil {
		t.Fatal("new source or installed artifact was discarded")
	}
}
