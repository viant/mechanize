// Command devcredential renews only the fixed local development-agent credential.
// It never adopts claims from the old token or prints signing material/tokens.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/mechanize/auth"
	"github.com/viant/scy"
	scyjwt "github.com/viant/scy/auth/jwt"
	"github.com/viant/scy/auth/jwt/signer"
	"github.com/viant/scy/auth/jwt/verifier"
)

type config struct {
	Keys       verifier.Config `json:"keys"`
	Policy     auth.Policy     `json:"identityPolicy"`
	Credential *scy.Resource   `json:"stdioCredential"`
	Users      []struct {
		Subject string `json:"subject"`
		Tenant  string `json:"tenant"`
	} `json:"users"`
}
type report struct {
	Renewed   bool   `json:"renewed"`
	ClientID  string `json:"clientId"`
	ExpiresAt int64  `json:"expiresAt"`
}

func private(path string) ([]byte, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || resolved != path {
		return nil, errors.New("canonical local file required")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) || owner.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		return nil, errors.New("private owned bounded file required")
	}
	b := make([]byte, info.Size())
	n, err := f.ReadAt(b, 0)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, errors.New("incomplete private read")
	}
	return b, nil
}

func renew(ctx context.Context, path string, apply bool) (report, error) {
	var result report
	raw, err := private(path)
	if err != nil {
		return result, err
	}
	var c config
	if err = json.Unmarshal(raw, &c); err != nil {
		return result, err
	}
	root := filepath.Dir(path)
	subject := fmt.Sprintf("local-uid-%d", os.Getuid())
	keyPath := filepath.Join(root, "credentials", "hmac")
	tokenPath := filepath.Join(root, "credentials", "stdio.jwt")
	if c.Policy.Issuer != fmt.Sprintf("mechanize:development:%d", os.Getuid()) || c.Policy.Audience != "mechanize-development" || len(c.Policy.Algorithms) != 1 || c.Policy.Algorithms[0] != "HS256" || c.Policy.Clients["development-agent"] == "" || c.Policy.TenantClaim != "" || len(c.Users) != 1 || c.Users[0].Subject != subject || c.Users[0].Tenant != "" {
		return result, errors.New("fixed local development identity required")
	}
	if c.Keys.HMAC == nil || c.Keys.HMAC.URL != keyPath || c.Keys.HMAC.Key != "" || c.Keys.HMAC.Fallback != nil || len(c.Keys.HMAC.Data) != 0 || len(c.Keys.RSA) != 0 || len(c.Keys.Rules) != 0 || c.Keys.CertURL != "" || c.Credential == nil || c.Credential.URL != tokenPath || c.Credential.Key != "" || c.Credential.Fallback != nil || len(c.Credential.Data) != 0 {
		return result, errors.New("fixed local development resource paths required")
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if apply {
		release, lockErr := renewalLock(filepath.Dir(tokenPath))
		if lockErr != nil {
			return result, lockErr
		}
		defer release()
	}
	key, err := private(keyPath)
	if err != nil {
		return result, err
	}
	old, err := private(tokenPath)
	if err != nil {
		return result, err
	}
	// Supplying Data prevents Scy's filesystem provider changing existing modes.
	resource := *c.Keys.HMAC
	resource.Data = key
	c.Keys.HMAC = &resource
	s := signer.New(&signer.Config{Rules: []*signer.Rule{{Resource: []string{c.Policy.Audience}, Algorithm: "HS256", HMAC: &resource}}})
	if err = s.Init(ctx); err != nil {
		return result, err
	}
	claims := &scyjwt.Claims{Scope: "desktop:observe desktop:control", RegisteredClaims: jwt.RegisteredClaims{Issuer: c.Policy.Issuer, Audience: jwt.ClaimStrings{c.Policy.Audience}, Subject: subject}}
	token, err := s.Create(24*time.Hour, claims, func(token *jwt.Token) {
		body, _ := json.Marshal(token.Claims)
		var mapped jwt.MapClaims
		_ = json.Unmarshal(body, &mapped)
		mapped["client_id"] = "development-agent"
		token.Claims = mapped
		if expiry, e := mapped.GetExpirationTime(); e == nil && expiry != nil {
			result.ExpiresAt = expiry.Unix()
		}
	})
	if err != nil {
		return result, err
	}
	v, err := auth.NewVerifier(ctx, &c.Keys, c.Policy)
	if err != nil {
		return result, err
	}
	p, err := v.Verify(ctx, token)
	if err != nil || p.Subject != subject || p.ClientID != "development-agent" || !p.HasScope("desktop:observe") || !p.HasScope("desktop:control") {
		return result, errors.New("renewed credential failed actual Mechanize verification")
	}
	result.ClientID = p.ClientID
	if !apply {
		return result, nil
	}
	for _, check := range []struct {
		path   string
		before []byte
	}{{path, raw}, {keyPath, key}, {tokenPath, old}} {
		now, e := private(check.path)
		if e != nil || !bytes.Equal(now, check.before) {
			return result, errors.New("enrollment changed during renewal")
		}
	}
	f, err := os.CreateTemp(filepath.Dir(tokenPath), ".stdio-renew-*")
	if err != nil {
		return result, err
	}
	defer os.Remove(f.Name())
	if _, err = f.WriteString(token); err != nil {
		f.Close()
		return result, err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return result, err
	}
	if err = f.Close(); err != nil {
		return result, err
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = os.Rename(f.Name(), tokenPath); err != nil {
		return result, err
	}
	result.Renewed = true
	return result, nil
}

func main() {
	path := flag.String("config", "", "private development config.json")
	apply := flag.Bool("apply", false, "replace only the development-agent token after Scy signing and verification")
	flag.Parse()
	r, err := renew(context.Background(), *path, *apply)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Development credential renewal rejected; secret details withheld")
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(r)
}
