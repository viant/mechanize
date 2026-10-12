package keychain

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRelocationOptionsBindBothPathsWithoutChangingV1(t *testing.T) {
	old := migrationFixtureOptions()
	raw, _ := json.Marshal([]string{old.canonicalExecutable, old.oldRequirement, old.newRequirement, old.alias, old.item.Service, old.item.Account})
	if migrationOptionsDigest(old) != migrationDigest(raw) {
		t.Fatal("v1 digest changed")
	}
	moved := old
	moved.newCanonicalExecutable = "/Users/fixture/Applications/Mechanize.app/Contents/Helpers/mechanize"
	if !validMigrationOptions(moved) || moved.destinationExecutable() != moved.newCanonicalExecutable {
		t.Fatal("closed relocation rejected")
	}
	fields := []string{old.canonicalExecutable, old.oldRequirement, old.newRequirement, old.alias, old.item.Service, old.item.Account, moved.newCanonicalExecutable, "mechanize-custody-relocation-v2"}
	raw, _ = json.Marshal(fields)
	if migrationOptionsDigest(moved) != migrationDigest(raw) || migrationOptionsDigest(moved) == migrationOptionsDigest(old) {
		t.Fatal("relocation digest unbound")
	}
	for _, path := range []string{old.canonicalExecutable, "relative", strings.Replace(moved.newCanonicalExecutable, "Mechanize.app", "Other.app", 1)} {
		bad := moved
		bad.newCanonicalExecutable = path
		if validMigrationOptions(bad) {
			t.Fatal("invalid relocation accepted")
		}
	}
}
