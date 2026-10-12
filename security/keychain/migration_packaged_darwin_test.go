//go:build darwin && cgo

package keychain

import (
	"context"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/mechanize/auth"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/jwt/verifier"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func privatePackagedFixture(t *testing.T) (string, migrationPackagedResource) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "resource")
	raw := []byte("fixture-private-data")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return dir, migrationPackagedResource{path, migrationDigest(raw)}
}
func TestMigrationPackagedResourceRequiresPrivateUnchangedCustody(t *testing.T) {
	_, ref := privatePackagedFixture(t)
	data, err := readMigrationPackagedResource(ref)
	if err != nil || string(data) != "fixture-private-data" {
		t.Fatal("private fixture rejected", err)
	}
	for _, mode := range []string{"digest", "public", "symlink", "hardlink", "parent"} {
		t.Run(mode, func(t *testing.T) {
			dir, r := privatePackagedFixture(t)
			switch mode {
			case "digest":
				r.SHA256 = migrationDigest([]byte("wrong"))
			case "public":
				os.Chmod(r.Path, 0644)
			case "symlink":
				os.Rename(r.Path, r.Path+".original")
				os.Symlink(r.Path+".original", r.Path)
			case "hardlink":
				os.Link(r.Path, filepath.Join(dir, "linked"))
			case "parent":
				os.Chmod(dir, 0755)
			}
			if data, err := readMigrationPackagedResource(r); err == nil || data != nil {
				t.Fatal("unqualified custody returned bytes")
			}
		})
	}
}
func TestMigrationPackagedVerifierPreservesExistingHMACScheme(t *testing.T) {
	dir, key := privatePackagedFixture(t)
	config := struct {
		Keys           verifier.Config `json:"keys"`
		IdentityPolicy auth.Policy     `json:"identityPolicy"`
	}{verifier.Config{HMAC: &scy.Resource{URL: key.Path}}, auth.Policy{Issuer: "fixture", Audience: "migration", Algorithms: []string{"HS256"}, Clients: map[string]string{"native-console": "Fixture console"}}}
	raw, _ := json.Marshal(config)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	enrollment := packagedFixture()
	enrollment.Config = migrationPackagedResource{path, migrationDigest(raw)}
	enrollment.Resources = []migrationPackagedResource{key}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	loaded, err := migrationPackagedVerifier(ctx, enrollment)
	if err != nil {
		t.Fatal("existing private HMAC scheme refused", err)
	}
	claims := jwt.MapClaims{"iss": "fixture", "aud": "migration", "sub": "owner", "client_id": "native-console", "scope": "consent:admin", "exp": time.Now().Add(time.Minute).Unix()}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("fixture-private-data"))
	if err != nil {
		t.Fatal(err)
	}
	principal, err := loaded.Verify(ctx, token)
	if err != nil || principal.ClientID != "native-console" || !principal.HasScope("consent:admin") {
		t.Fatal("existing admin verification changed", err)
	}
	wrong, _ := jwt.NewWithClaims(jwt.SigningMethodHS384, claims).SignedString([]byte("fixture-private-data"))
	if _, err := loaded.Verify(ctx, wrong); err == nil {
		t.Fatal("original algorithm policy widened")
	}
	config.Keys.HMAC.Data = []byte("forbidden inline secret")
	raw, _ = json.Marshal(config)
	os.WriteFile(path, raw, 0600)
	enrollment.Config.SHA256 = migrationDigest(raw)
	if _, err := migrationPackagedVerifier(ctx, enrollment); err == nil {
		t.Fatal("inline key material accepted")
	}
}

func TestMigrationPackagedPeerPrimingDoesNotConsumeData(t *testing.T) {
	for _, mode := range []string{"empty", "data", "closed"} {
		t.Run(mode, func(t *testing.T) {
			pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
			if err != nil {
				t.Fatal(err)
			}
			left := os.NewFile(uintptr(pair[0]), "fixture-console")
			right := os.NewFile(uintptr(pair[1]), "fixture-peer")
			defer right.Close()
			raw, err := net.FileConn(left)
			left.Close()
			if err != nil {
				t.Fatal(err)
			}
			console := raw.(*net.UnixConn)
			defer console.Close()
			if mode == "data" {
				if _, err = right.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "closed" {
				right.Close()
			}
			if migrationPrimeConsolePeer(console) != (mode == "empty") {
				t.Fatal("wrong no-data admission")
			}
			if mode == "data" {
				var value [1]byte
				if _, err = console.Read(value[:]); err != nil || value[0] != 'x' {
					t.Fatal("peek consumed data", err)
				}
			}
		})
	}
}
