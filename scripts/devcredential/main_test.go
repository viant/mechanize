package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/jwt/verifier"
)

func fixture(t *testing.T) (string, config) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(root, "credentials"), 0700); err != nil {
		t.Fatal(err)
	}
	c := config{Keys: verifier.Config{HMAC: &scy.Resource{URL: filepath.Join(root, "credentials", "hmac")}}, Policy: auth.Policy{Issuer: fmt.Sprintf("mechanize:development:%d", os.Getuid()), Audience: "mechanize-development", Algorithms: []string{"HS256"}, Clients: map[string]string{"development-agent": "Local development agent"}}, Credential: &scy.Resource{URL: filepath.Join(root, "credentials", "stdio.jwt")}}
	user := struct {
		Subject string `json:"subject"`
		Tenant  string `json:"tenant"`
	}{Subject: fmt.Sprintf("local-uid-%d", os.Getuid())}
	c.Users = append(c.Users, user)
	if err = os.WriteFile(c.Keys.HMAC.URL, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(c.Credential.URL, []byte("old-opaque-token-not-used-as-claims"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "config.json")
	save(t, path, c)
	return path, c
}
func save(t *testing.T, path string, c config) {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestScyRenewalPreservesIdentityScopesAndPrivateFiles(t *testing.T) {
	path, c := fixture(t)
	ctx := context.Background()
	key, _ := private(c.Keys.HMAC.URL)
	configuration, _ := private(path)
	old, _ := private(c.Credential.URL)
	r, err := renew(ctx, path, false)
	if err != nil || r.Renewed {
		t.Fatalf("dry run %+v %v", r, err)
	}
	if b, _ := private(c.Credential.URL); !bytes.Equal(b, old) {
		t.Fatal("dry run replaced credential")
	}
	r, err = renew(ctx, path, true)
	if err != nil || !r.Renewed || r.ClientID != "development-agent" {
		t.Fatalf("renewal %+v %v", r, err)
	}
	if r.ExpiresAt < time.Now().Add(23*time.Hour).Unix() || r.ExpiresAt > time.Now().Add(25*time.Hour).Unix() {
		t.Fatal("unbounded expiry")
	}
	for p, want := range map[string][]byte{path: configuration, c.Keys.HMAC.URL: key} {
		b, e := private(p)
		if e != nil || !bytes.Equal(b, want) {
			t.Fatal("enrollment changed")
		}
	}
	resource := *c.Keys.HMAC
	resource.Data = key
	c.Keys.HMAC = &resource
	v, err := auth.NewVerifier(ctx, &c.Keys, c.Policy)
	if err != nil {
		t.Fatal(err)
	}
	b, err := private(c.Credential.URL)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := v.Verify(ctx, string(b))
	if err != nil || principal.Subject != c.Users[0].Subject || principal.ClientID != "development-agent" || principal.HasScope("consent:admin") || len(principal.Scopes) != 2 {
		t.Fatalf("wrong issued authority %v", err)
	}
}
func TestRenewalRejectsForeignIdentityAndResources(t *testing.T) {
	for _, name := range []string{"issuer", "subject", "client", "resource", "tenant"} {
		t.Run(name, func(t *testing.T) {
			path, c := fixture(t)
			oldPath := c.Credential.URL
			old, _ := private(oldPath)
			switch name {
			case "issuer":
				c.Policy.Issuer = "external-provider"
			case "subject":
				c.Users[0].Subject = "another-user"
			case "client":
				delete(c.Policy.Clients, "development-agent")
			case "resource":
				c.Credential.URL = filepath.Join(filepath.Dir(path), "foreign-token")
			case "tenant":
				c.Policy.TenantClaim = "tenant"
			}
			save(t, path, c)
			if _, err := renew(context.Background(), path, true); err == nil {
				t.Fatal("foreign enrollment renewed")
			}
			b, _ := private(oldPath)
			if !bytes.Equal(b, old) {
				t.Fatal("rejected request changed token")
			}
		})
	}
}
func TestRenewalRejectsSymlinkAndSharedToken(t *testing.T) {
	for _, link := range []bool{false, true} {
		path, c := fixture(t)
		if link {
			original := c.Credential.URL + ".old"
			if err := os.Rename(c.Credential.URL, original); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(original, c.Credential.URL); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.Chmod(c.Credential.URL, 0640); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := renew(context.Background(), path, true); err == nil {
			t.Fatal("unsafe token destination accepted")
		}
	}
}
