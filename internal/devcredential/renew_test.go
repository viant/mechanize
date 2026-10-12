package devcredential

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/mechanize/auth"
	"github.com/viant/scy"
	scyjwt "github.com/viant/scy/auth/jwt"
	"github.com/viant/scy/auth/jwt/signer"
	"github.com/viant/scy/auth/jwt/verifier"
)

func fixture(t *testing.T) (string, Config) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Configuration and configured credentials intentionally have different
	// roots, matching installations that retain their original credential store.
	configRoot := filepath.Join(root, "current")
	credentialRoot := filepath.Join(root, "retained", "credentials")
	for _, dir := range []string{configRoot, credentialRoot} {
		if err = os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	c := Config{Keys: verifier.Config{HMAC: &scy.Resource{URL: filepath.Join(credentialRoot, "hmac")}}, Policy: auth.Policy{Issuer: fmt.Sprintf("mechanize:development:%d", os.Getuid()), Audience: "mechanize-development", Algorithms: []string{"HS256"}, Clients: map[string]string{"development-agent": "Development agent"}}, Credential: &scy.Resource{URL: filepath.Join(credentialRoot, "stdio.jwt")}}
	c.Users = append(c.Users, struct {
		Subject string `json:"subject"`
		Tenant  string `json:"tenant"`
	}{Subject: fmt.Sprintf("local-uid-%d", os.Getuid())})
	if err = os.WriteFile(c.Keys.HMAC.URL, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{37}, 32))), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(c.Credential.URL, []byte("initial-opaque-operator-fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(configRoot, "config.json")
	save(t, path, c)
	return path, c
}
func save(t *testing.T, path string, c Config) {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func seed(t *testing.T, path string, remaining time.Duration, change func(jwt.MapClaims)) string {
	t.Helper()
	e, err := readEnrollment(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	keys := e.keys()
	s := signer.New(&signer.Config{Rules: []*signer.Rule{{Resource: []string{e.config.Policy.Audience}, Algorithm: "HS256", HMAC: keys.HMAC}}})
	if err = s.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	claims := &scyjwt.Claims{Scope: "desktop:observe desktop:control", RegisteredClaims: jwt.RegisteredClaims{Issuer: e.config.Policy.Issuer, Subject: e.config.Users[0].Subject, Audience: jwt.ClaimStrings{e.config.Policy.Audience}}}
	raw, err := s.Create(Lifetime, claims, func(token *jwt.Token) {
		body, _ := json.Marshal(token.Claims)
		var mapped jwt.MapClaims
		_ = json.Unmarshal(body, &mapped)
		now := time.Now()
		mapped["client_id"] = "development-agent"
		mapped["iat"] = now.Add(-2 * time.Hour).Unix()
		mapped["nbf"] = now.Add(-2 * time.Hour).Unix()
		mapped["exp"] = now.Add(remaining).Unix()
		if change != nil {
			change(mapped)
		}
		token.Claims = mapped
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(e.tokenPath, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	return raw
}
func assertValid(t *testing.T, path, raw string) {
	t.Helper()
	e, err := readEnrollment(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	keys := e.keys()
	v, err := auth.NewVerifier(context.Background(), &keys, e.config.Policy)
	if err != nil {
		t.Fatal(err)
	}
	p, err := v.Verify(context.Background(), raw)
	if err != nil || !fixedPrincipal(p) || p.HasScope("consent:admin") {
		t.Fatal("returned credential failed current verifier or fixed authority")
	}
}
func TestAutomaticRenewalUsesConfiguredPrivateResourcesAndFixedAuthority(t *testing.T) {
	for _, remaining := range []time.Duration{30 * time.Minute, -time.Hour} {
		t.Run(remaining.String(), func(t *testing.T) {
			path, c := fixture(t)
			old := seed(t, path, remaining, nil)
			configuration, _ := PrivateRead(path)
			key, _ := PrivateRead(c.Keys.HMAC.URL)
			raw, handled, err := Load(context.Background(), path)
			if err != nil || !handled || raw == old {
				t.Fatal("eligible credential was not renewed", err)
			}
			assertValid(t, path, raw)
			e, err := readEnrollment(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			_, expiry, err := inspect(context.Background(), e)
			if err != nil || time.Until(expiry) < 23*time.Hour || time.Until(expiry) > 24*time.Hour {
				t.Fatal("renewal lifetime was not bounded to 24h")
			}
			if !bytes.Equal(configuration, e.raw) || !bytes.Equal(key, e.key) || string(e.old) != raw {
				t.Fatal("renewal changed enrollment or did not publish returned credential")
			}
			for _, file := range []string{path, c.Keys.HMAC.URL, c.Credential.URL} {
				info, err := os.Stat(file)
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatal("renewal changed private file mode")
				}
			}
			again, handled, err := Load(context.Background(), path)
			if err != nil || !handled || again != raw {
				t.Fatal("healthy credential was unnecessarily reissued")
			}
		})
	}
}
func TestAutomaticRenewalRejectsSignatureIdentityAndTemporalFailures(t *testing.T) {
	for _, kind := range []string{"badSignature", "rotatedKey", "removedClient", "foreignClient", "subject", "issuer", "audience", "adminScope", "missingScope", "duplicateScope", "futureIssuedAt", "futureNotBefore", "missingExpiration", "invalidExpiration", "missingToken", "missingKey"} {
		t.Run(kind, func(t *testing.T) {
			path, c := fixture(t)
			seed(t, path, -time.Hour, func(m jwt.MapClaims) {
				switch kind {
				case "foreignClient":
					m["client_id"] = "console-admin"
				case "subject":
					m["sub"] = "foreign-subject"
				case "issuer":
					m["iss"] = "external-provider"
				case "audience":
					m["aud"] = []string{"foreign-audience"}
				case "adminScope":
					m["scope"] = "desktop:observe desktop:control consent:admin"
				case "missingScope":
					m["scope"] = "desktop:observe"
				case "duplicateScope":
					m["scope"] = "desktop:observe desktop:observe"
				case "futureIssuedAt":
					m["iat"] = time.Now().Add(time.Hour).Unix()
					m["exp"] = time.Now().Add(2 * time.Hour).Unix()
				case "futureNotBefore":
					m["nbf"] = time.Now().Add(time.Hour).Unix()
				case "missingExpiration":
					delete(m, "exp")
				case "invalidExpiration":
					m["exp"] = "not-a-time"
				}
			})
			switch kind {
			case "badSignature":
				b, _ := PrivateRead(c.Credential.URL)
				if b[bytes.LastIndexByte(b, '.')+1] == 'a' {
					b[bytes.LastIndexByte(b, '.')+1] = 'b'
				} else {
					b[bytes.LastIndexByte(b, '.')+1] = 'a'
				}
				if err := os.WriteFile(c.Credential.URL, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "rotatedKey":
				if err := os.WriteFile(c.Keys.HMAC.URL, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{43}, 32))), 0600); err != nil {
					t.Fatal(err)
				}
			case "removedClient":
				delete(c.Policy.Clients, "development-agent")
				save(t, path, c)
			case "missingToken":
				if err := os.Remove(c.Credential.URL); err != nil {
					t.Fatal(err)
				}
			case "missingKey":
				if err := os.Remove(c.Keys.HMAC.URL); err != nil {
					t.Fatal(err)
				}
			}
			before, readErr := PrivateRead(c.Credential.URL)
			raw, handled, err := Load(context.Background(), path)
			if kind == "removedClient" {
				if handled || err != nil || raw != "" {
					t.Fatal("noneligible enrollment was altered")
				}
			} else if err == nil || raw != "" {
				t.Fatal("ineligible old credential renewed", kind)
			}
			after, afterErr := PrivateRead(c.Credential.URL)
			if (readErr == nil) != (afterErr == nil) || !bytes.Equal(before, after) {
				t.Fatal("refused renewal changed credential")
			}
		})
	}
}
func TestAutomaticRenewalDoesNotTouchOtherIdentityProviders(t *testing.T) {
	for _, kind := range []string{"issuer", "algorithm", "tenant", "adminPolicy"} {
		t.Run(kind, func(t *testing.T) {
			path, c := fixture(t)
			seed(t, path, time.Minute, nil)
			switch kind {
			case "issuer":
				c.Policy.Issuer = "external-oidc"
			case "algorithm":
				c.Policy.Algorithms = []string{"RS256"}
			case "tenant":
				c.Policy.TenantClaim = "tenant"
			case "adminPolicy":
				c.Policy.RequiredScopes = []string{"consent:admin"}
			}
			save(t, path, c)
			before, _ := PrivateRead(c.Credential.URL)
			raw, handled, err := Load(context.Background(), path)
			if err != nil || handled || raw != "" {
				t.Fatal("nonlocal provider was intercepted")
			}
			after, _ := PrivateRead(c.Credential.URL)
			if !bytes.Equal(before, after) {
				t.Fatal("nonlocal credential changed")
			}
		})
	}
}
func TestAutomaticRenewalConcurrentAndBusyLockAreBounded(t *testing.T) {
	path, c := fixture(t)
	old := seed(t, path, time.Minute, nil)
	release, err := Lock(filepath.Dir(c.Credential.URL))
	if err != nil {
		t.Fatal(err)
	}
	raw, handled, err := Load(context.Background(), path)
	if err != nil || !handled || raw != old {
		t.Fatal("busy lock did not preserve still-valid verified credential")
	}
	release()
	var wg sync.WaitGroup
	var mu sync.Mutex
	returned := []string{}
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			raw, handled, err := Load(context.Background(), path)
			mu.Lock()
			defer mu.Unlock()
			if err != nil || !handled {
				t.Error("concurrent renewal failed", err)
				return
			}
			returned = append(returned, raw)
		}()
	}
	wg.Wait()
	if len(returned) != 16 {
		t.Fatal("concurrent calls were lost")
	}
	for _, raw := range returned {
		assertValid(t, path, raw)
	}
	published, _ := PrivateRead(c.Credential.URL)
	if string(published) == old {
		t.Fatal("no cooperating call renewed credential")
	}
	seed(t, path, -time.Hour, nil)
	release, err = Lock(filepath.Dir(c.Credential.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	raw, handled, err = Load(context.Background(), path)
	if !handled || raw != "" || !errors.Is(err, ErrRenewalActive) {
		t.Fatal("busy renewal returned an expired credential")
	}
}
func TestAutomaticRenewalRejectsUnsafePublicationAndHonorsComparison(t *testing.T) {
	for _, kind := range []string{"tokenSymlink", "tokenHardlink", "keySymlink", "directorySymlink", "sharedDirectory", "foreignBasename", "differentParent", "inlineKey", "canceled", "comparisonChanged"} {
		t.Run(kind, func(t *testing.T) {
			path, c := fixture(t)
			seed(t, path, time.Minute, nil)
			switch kind {
			case "tokenSymlink", "keySymlink":
				target := c.Credential.URL
				if kind == "keySymlink" {
					target = c.Keys.HMAC.URL
				}
				if err := os.Rename(target, target+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target+".real", target); err != nil {
					t.Fatal(err)
				}
			case "tokenHardlink":
				if err := os.Link(c.Credential.URL, c.Credential.URL+".link"); err != nil {
					t.Fatal(err)
				}
			case "directorySymlink":
				dir := filepath.Dir(c.Credential.URL)
				if err := os.Rename(dir, dir+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dir+".real", dir); err != nil {
					t.Fatal(err)
				}
			case "sharedDirectory":
				if err := os.Chmod(filepath.Dir(c.Credential.URL), 0777); err != nil {
					t.Fatal(err)
				}
			case "foreignBasename":
				c.Credential.URL = filepath.Join(filepath.Dir(c.Credential.URL), "foreign.jwt")
				save(t, path, c)
			case "differentParent":
				c.Keys.HMAC.URL = filepath.Join(filepath.Dir(path), "hmac")
				save(t, path, c)
			case "inlineKey":
				c.Keys.HMAC.Data = []byte("untrusted-inline-fixture")
				save(t, path, c)
			case "comparisonChanged":
				e, err := readEnrollment(context.Background(), path)
				if err != nil {
					t.Fatal(err)
				}
				before, _ := PrivateRead(c.Credential.URL)
				if err = os.WriteFile(c.Keys.HMAC.URL, []byte("changed-fixture-key"), 0600); err != nil {
					t.Fatal(err)
				}
				if publish(context.Background(), e, "never-published") == nil {
					t.Fatal("changed enrollment published")
				}
				after, _ := PrivateRead(c.Credential.URL)
				if !bytes.Equal(before, after) {
					t.Fatal("failed comparison changed token")
				}
				return
			}
			ctx := context.Background()
			if kind == "canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if raw, _, err := Load(ctx, path); err == nil || raw != "" {
				t.Fatal("unsafe renewal admitted", kind)
			}
		})
	}
}
