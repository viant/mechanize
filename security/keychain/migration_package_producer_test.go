//go:build darwin || linux

package keychain

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// Shared with the Python producer: struct order, map-key order, optional field
// omission and nested inventory entry order must match the installer's decoder.
func TestRuntimePackageProducerCanonicalGolden(t *testing.T) {
	for _, fixture := range []string{"runtime-upgrade-plan-v1.json", "runtime-upgrade-plan-runtime-resources-v1.json", "runtime-upgrade-plan-unified-v2.json", "runtime-upgrade-plan-preinstalled-v2.json"} {
		raw, err := os.ReadFile("../../testdata/" + fixture)
		if err != nil {
			t.Fatal(err)
		}
		var plan migrationPackagedInstallPlan
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&plan); err != nil {
			t.Fatal(err)
		}
		actual, err := json.Marshal(plan)
		if err != nil || !bytes.Equal(actual, raw) {
			t.Fatal("Python package plan differs from Go canonical wire encoding", err)
		}
		if plan.Version == 1 && !validMigrationExtensionMode(plan.Runtime) {
			t.Fatal("preserved extension contract invalid", fixture)
		}
		for _, a := range plan.Runtime.Artifacts {
			if (a.Role != "unified-app" && a.OldDigest != runtimeInventoryDigest(a.Old)) || a.NewDigest != runtimeInventoryDigest(a.New) {
				t.Fatal("cross-language inventory digest mismatch")
			}
		}
	}
}
