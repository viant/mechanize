package chrome

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/scy"
)

func TestBrokerStartupDecryptsRealScyEnvKeyEnrollment(t *testing.T) {
	const envKey = "MECHANIZE_TEST_BROKER_ENROLLMENT_KEY"
	t.Setenv(envKey, "fixture-encryption-key-32-bytes-xx")
	dir, dirErr := os.MkdirTemp("", "mscy-")
	if dirErr != nil {
		t.Fatal(dirErr)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	dir, dirErr = filepath.EvalSymlinks(dir)
	if dirErr != nil {
		t.Fatal(dirErr)
	}
	os.Chmod(dir, 0700)
	credentialDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credentialDir, 0700); err != nil {
		t.Fatal(err)
	}
	resource := scy.Resource{URL: filepath.Join(credentialDir, "enrollment.sec"), Key: "blowfish://env/" + envKey}
	fixtureCredential := strings.Repeat("fixture-only-enrollment-", 3)
	if err := scy.New().Store(context.Background(), scy.NewSecret(fixtureCredential, &resource)); err != nil {
		t.Fatal("real encrypted fixture resource store failed")
	}
	ciphertext, err := os.ReadFile(resource.URL)
	if err != nil || len(ciphertext) == 0 || bytes.Contains(ciphertext, []byte(fixtureCredential)) {
		t.Fatal("fixture resource is not encrypted on disk")
	}
	os.Chmod(resource.URL, 0600)
	os.Chmod(dir, 0700)
	p, _ := auth.NewPrincipal("fixture:issuer", "", "fixture-owner", []string{"desktop:observe"})
	grant := Enrollment{Principal: p, ProfileChannel: "encrypted-profile", BrowserInstance: "encrypted-browser", ExtensionOrigin: "chrome-extension://" + strings.Repeat("a", 32) + "/", Origins: []string{"https://fixture.test"}, CredentialResource: resource}
	cfg := Config{FixtureEnrollment: true, SocketPath: filepath.Join(dir, "broker.sock"), Grants: []Enrollment{grant}}
	broker, err := NewBroker(context.Background(), cfg)
	if err != nil {
		t.Fatal("broker startup could not load registered encrypted Scy env-key resource")
	}
	if broker.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)].credential != fixtureCredential {
		broker.Close()
		t.Fatal("broker did not decrypt exact raw enrollment resource")
	}
	broker.Close()
	t.Setenv(envKey, "")
	cfg.SocketPath = filepath.Join(dir, "missing-key.sock")
	if broker, err = NewBroker(context.Background(), cfg); err == nil {
		broker.Close()
		t.Fatal("missing explicit env key accepted a fallback")
	}
}
