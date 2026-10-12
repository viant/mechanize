//go:build darwin || linux

package keychain

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func preserveRuntimeFixture(t *testing.T) *runtimePlacementFixture {
	f := newRuntimePlacementFixture(t)
	ext := f.r.artifact("extension")
	plan := f.r.plan
	plan.Mode = preserveExtensionMode
	plan.ChromeRequirement = "signed-Chrome-requirement"
	plan.ExtensionStorageSHA256 = ""
	plan.PreservedExtension = &migrationPreservedExtension{Path: ext.Target, ExtensionID: plan.ExtensionID, Inventory: runtimeInventoryCopy(ext.Old), InventorySHA256: ext.OldDigest}
	plan.Artifacts = nil
	for _, a := range f.r.plan.Artifacts {
		if a.Role != "extension" {
			plan.Artifacts = append(plan.Artifacts, a)
		}
	}
	f.observer.observation.mode = preserveExtensionMode
	f.observer.observation.storageSHA256 = ""
	var err error
	f.r, err = newRuntimeArtifactsWith(plan, f.journal, f.observer, f.signatures)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func TestPreserveExtensionPlacesRuntimeWithoutAnyExtensionExchange(t *testing.T) {
	f := preserveRuntimeFixture(t)
	p := f.r.plan.PreservedExtension
	before, err := os.Stat(p.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.r.inspectPrepared(f.ctx, f.p); err != nil {
		t.Fatal(err)
	}
	if err = f.r.placeNonConsole(f.ctx, f.p, f.check); err != nil {
		t.Fatal(err)
	}
	if err = f.r.placeConsoleTerminal(f.ctx, f.p, f.localReceipt(), f.check); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(p.Path)
	if err != nil || !os.SameFile(before, after) || runtimeVerifyInventory(p.Path, p.Inventory) != nil {
		t.Fatal("preserved extension changed")
	}
	if _, err = os.Stat(filepath.Join(filepath.Dir(p.Path), ".runtime-exchange-"+f.p.transitionID+"-extension")); !os.IsNotExist(err) {
		t.Fatal("extension staged/exchanged")
	}
	if f.r.plan.ExtensionStorageSHA256 != "" {
		t.Fatal("fabricated storage observation")
	}
	record, _ := f.journal.load(f.ctx)
	if record.state != migrationVerified {
		t.Fatal("runtime verification missing")
	}
}
func TestPreserveExtensionRejectsMutationAndAmbiguousVariants(t *testing.T) {
	for _, mode := range []string{"mode", "storage claim", "extension artifact", "overlap candidate", "changed code", "wrong observer mode"} {
		t.Run(mode, func(t *testing.T) {
			f := preserveRuntimeFixture(t)
			plan := f.r.plan
			switch mode {
			case "mode":
				plan.Mode = "other"
			case "storage claim":
				plan.ExtensionStorageSHA256 = strings.Repeat("b", 64)
			case "extension artifact":
				plan.Artifacts = append(plan.Artifacts, migrationRuntimeArtifact{Role: "extension"})
			case "overlap candidate":
				plan.Artifacts[0].Candidate = filepath.Join(plan.PreservedExtension.Path, "candidate")
			case "changed code":
				if err := os.WriteFile(filepath.Join(plan.PreservedExtension.Path, "worker.js"), []byte("changed synthetic code"), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong observer mode":
				f.observer.observation.mode = ""
			}
			candidate, err := newRuntimeArtifactsWith(plan, f.journal, f.observer, f.signatures)
			if mode == "changed code" || mode == "wrong observer mode" {
				if err != nil {
					t.Fatal(err)
				}
				if candidate.inspectPrepared(f.ctx, f.p) == nil {
					t.Fatal("unqualified preservation accepted")
				}
			} else if err == nil {
				t.Fatal("ambiguous variant accepted")
			}
		})
	}
}
func TestPreservationWriteSetCannotEscapeRuntimeOrOverlapPreservedCode(t *testing.T) {
	f := preserveRuntimeFixture(t)
	root := filepath.Dir(f.r.plan.BrokerPath)
	enrolled := migrationPackagedEnrollment{CanonicalExecutable: f.r.plan.BrokerPath, Config: migrationPackagedResource{Path: filepath.Join(root, "config.json")}, JournalRoot: filepath.Join(root, "acl-journal")}
	p := migrationPackagedInstallPlan{Runtime: f.r.plan, Backup: filepath.Join(root, "backup"), StageJournalRoot: filepath.Join(root, "stage-journal"), ArtifactJournalRoot: filepath.Join(root, "artifact-journal"), NewSourceRoot: filepath.Join(root, "source"), BrokerCandidate: migrationPackagedResource{Path: filepath.Join(root, "candidate-broker")}, ConfigCandidate: migrationPackagedResource{Path: filepath.Join(root, "candidate-config")}}
	if !validPreservationPlacement(p, enrolled) {
		t.Fatal("closed runtime write set rejected")
	}
	for _, field := range []string{"backup", "stage", "artifact", "acl", "candidate"} {
		modified, owner := p, enrolled
		switch field {
		case "backup":
			modified.Backup = filepath.Join(filepath.Dir(root), "Chrome-profile", "backup")
		case "stage":
			modified.StageJournalRoot = p.Runtime.PreservedExtension.Path
		case "artifact":
			modified.ArtifactJournalRoot = filepath.Dir(p.Runtime.PreservedExtension.Path)
		case "acl":
			owner.JournalRoot = p.Runtime.PreservedExtension.Path
		case "candidate":
			modified.ConfigCandidate.Path = filepath.Join(p.Runtime.PreservedExtension.Path, "candidate")
		}
		if validPreservationPlacement(modified, owner) {
			t.Fatal("unsafe write overlap accepted", field)
		}
	}
}
func TestPreserveObserverProtocolHasNoStorageOrConnectedClaim(t *testing.T) {
	req := migrationObserverRequest{Version: 1, Nonce: strings.Repeat("1", 64), Session: strings.Repeat("2", 64), ManifestSHA256: strings.Repeat("3", 64), DeadlineUnixMilliseconds: time.Now().Add(time.Second).UnixMilli(), Mode: preserveExtensionMode}
	payload, _ := json.Marshal(req)
	response := observerResponseFixture(req, payload)
	response.Mode = preserveExtensionMode
	response.StorageSHA256 = ""
	raw, _ := json.Marshal(response)
	if strings.Contains(string(raw), "storageSHA256") || strings.Contains(string(raw), "nativeConnected") {
		t.Fatal("unobserved facts serialized")
	}
	if _, err := decodeMigrationObserverResponse(raw, req, payload); err != nil {
		t.Fatal(err)
	}
	response.StorageSHA256 = strings.Repeat("b", 64)
	raw, _ = json.Marshal(response)
	if _, err := decodeMigrationObserverResponse(raw, req, payload); err == nil {
		t.Fatal("preservation accepted storage claim")
	}
	req.Mode = ""
	payload, _ = json.Marshal(req)
	response.Mode = ""
	response.StorageSHA256 = ""
	raw, _ = json.Marshal(response)
	if _, err := decodeMigrationObserverResponse(raw, req, payload); err == nil {
		t.Fatal("full mode lost storage requirement")
	}
}

func TestPreserveChromeRequirementMustMatchOriginalFrozenConfiguration(t *testing.T) {
	runtime := migrationRuntimeArtifactPlan{Mode: preserveExtensionMode, ChromeExecutable: "/Applications/Chrome", ChromeRequirement: "original-signed-Chrome"}
	for _, mode := range []string{"exact", "missing", "changed executable", "changed pin"} {
		old := map[string]any{"chrome": map[string]any{"processTrust": map[string]any{"chromeExecutable": runtime.ChromeExecutable, "chromeRequirement": runtime.ChromeRequirement}}}
		switch mode {
		case "missing":
			delete(old, "chrome")
		case "changed executable":
			old["chrome"].(map[string]any)["processTrust"].(map[string]any)["chromeExecutable"] = "/private/other"
		case "changed pin":
			old["chrome"].(map[string]any)["processTrust"].(map[string]any)["chromeRequirement"] = "other"
		}
		if preservedChromeConfigMatches(runtime, old) != (mode == "exact") {
			t.Fatal("Chrome pin dependency changed", mode)
		}
	}
}

func TestPreserveRuntimeResourcesOnlyIgnoresSiblingsButPinsEveryCodeFile(t *testing.T) {
	f := preserveRuntimeFixture(t)
	p := f.r.plan.PreservedExtension
	for _, name := range runtimeExtensionFiles {
		if _, ok := p.Inventory[name]; !ok {
			t.Fatal("fixture lacks current resource", name)
		}
	}
	p.RuntimeResourcesOnly = true
	extra := filepath.Join(p.Path, "node_modules")
	if err := os.Mkdir(extra, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/does-not-exist", filepath.Join(extra, "unread")); err != nil {
		t.Fatal(err)
	}
	if err := verifyPreservedInventory(p); err != nil {
		t.Fatal("runtime-only rejected unrelated unread sibling", err)
	}
	p.RuntimeResourcesOnly = false
	if verifyPreservedInventory(p) == nil {
		t.Fatal("strict mode accepted extra directory")
	}
	p.RuntimeResourcesOnly = true
	file := filepath.Join(p.Path, "content.js")
	if err := os.WriteFile(file, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if verifyPreservedInventory(p) == nil {
		t.Fatal("changed runtime bytes accepted")
	}
}
