// Package devcredential renews only the operator-enrolled local development identity.
package devcredential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/mechanize/auth"
	"github.com/viant/scy"
	scyjwt "github.com/viant/scy/auth/jwt"
	"github.com/viant/scy/auth/jwt/signer"
	"github.com/viant/scy/auth/jwt/verifier"
)

const Lifetime = 24 * time.Hour
const RenewalWindow = time.Hour

// Config is the existing enrollment subset; it introduces no identity settings.
type Config struct {
	Keys       verifier.Config `json:"keys"`
	Policy     auth.Policy     `json:"identityPolicy"`
	Credential *scy.Resource   `json:"stdioCredential"`
	Users      []struct {
		Subject string `json:"subject"`
		Tenant  string `json:"tenant"`
	} `json:"users"`
}
type Report struct {
	Renewed   bool   `json:"renewed"`
	ClientID  string `json:"clientId"`
	ExpiresAt int64  `json:"expiresAt"`
}
type enrollment struct {
	config                   Config
	path, keyPath, tokenPath string
	raw, key, old            []byte
}

func PrivateRead(path string) ([]byte, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || resolved != path {
		return nil, errors.New("canonical local file required")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("private file unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, errors.New("private file unavailable")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) || owner.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		return nil, errors.New("private owned bounded file required")
	}
	b := make([]byte, info.Size())
	n, err := f.ReadAt(b, 0)
	if err != nil || n != len(b) {
		return nil, errors.New("incomplete private read")
	}
	return b, nil
}
func eligible(c Config) bool {
	if c.Policy.Issuer != fmt.Sprintf("mechanize:development:%d", os.Getuid()) || c.Policy.Audience != "mechanize-development" || len(c.Policy.Algorithms) != 1 || c.Policy.Algorithms[0] != "HS256" || strings.TrimSpace(c.Policy.Clients["development-agent"]) == "" || c.Policy.TenantClaim != "" || len(c.Users) != 1 || c.Users[0].Subject != fmt.Sprintf("local-uid-%d", os.Getuid()) || c.Users[0].Tenant != "" {
		return false
	}
	for _, scope := range c.Policy.RequiredScopes {
		if scope != "desktop:observe" && scope != "desktop:control" {
			return false
		}
	}
	return true
}
func fileResource(r *scy.Resource) bool {
	return r != nil && filepath.IsAbs(r.URL) && filepath.Clean(r.URL) == r.URL && r.Key == "" && r.Fallback == nil && len(r.Data) == 0
}
func paths(c Config) (string, string, error) {
	if !fileResource(c.Keys.HMAC) || !fileResource(c.Credential) || len(c.Keys.RSA) != 0 || len(c.Keys.Rules) != 0 || c.Keys.CertURL != "" || filepath.Base(c.Keys.HMAC.URL) != "hmac" || filepath.Base(c.Credential.URL) != "stdio.jwt" || filepath.Dir(c.Keys.HMAC.URL) != filepath.Dir(c.Credential.URL) {
		return "", "", errors.New("fixed local development resource paths required")
	}
	if err := privateDirectory(filepath.Dir(c.Credential.URL)); err != nil {
		return "", "", err
	}
	return c.Keys.HMAC.URL, c.Credential.URL, nil
}
func readConfig(path string) ([]byte, Config, error) {
	raw, err := PrivateRead(path)
	var c Config
	if err != nil {
		return nil, c, err
	}
	if json.Unmarshal(raw, &c) != nil {
		return nil, c, errors.New("development configuration unavailable")
	}
	return raw, c, nil
}
func readEnrollment(ctx context.Context, path string) (enrollment, error) {
	e := enrollment{path: path}
	var err error
	if err = ctx.Err(); err != nil {
		return e, err
	}
	e.raw, e.config, err = readConfig(path)
	if err != nil {
		return e, err
	}
	if !eligible(e.config) {
		return e, errors.New("fixed local development identity required")
	}
	e.keyPath, e.tokenPath, err = paths(e.config)
	if err != nil {
		return e, err
	}
	e.key, err = PrivateRead(e.keyPath)
	if err != nil {
		return e, err
	}
	e.old, err = PrivateRead(e.tokenPath)
	return e, err
}
func (e enrollment) keys() verifier.Config {
	keys := e.config.Keys
	resource := *keys.HMAC
	resource.Data = e.key // Scy must not reopen or alter enrollment file modes.
	keys.HMAC = &resource
	return keys
}
func (e enrollment) unchanged() error {
	for _, check := range []struct {
		path   string
		before []byte
	}{{e.path, e.raw}, {e.keyPath, e.key}, {e.tokenPath, e.old}} {
		now, err := PrivateRead(check.path)
		if err != nil || !bytes.Equal(now, check.before) {
			return errors.New("enrollment changed during renewal")
		}
	}
	return privateDirectory(filepath.Dir(e.tokenPath))
}
func mint(ctx context.Context, e enrollment) (string, Report, error) {
	var result Report
	keys := e.keys()
	s := signer.New(&signer.Config{Rules: []*signer.Rule{{Resource: []string{e.config.Policy.Audience}, Algorithm: "HS256", HMAC: keys.HMAC}}})
	if err := s.Init(ctx); err != nil {
		return "", result, errors.New("development signer unavailable")
	}
	claims := &scyjwt.Claims{Scope: "desktop:observe desktop:control", RegisteredClaims: jwt.RegisteredClaims{Issuer: e.config.Policy.Issuer, Audience: jwt.ClaimStrings{e.config.Policy.Audience}, Subject: fmt.Sprintf("local-uid-%d", os.Getuid())}}
	token, err := s.Create(Lifetime, claims, func(token *jwt.Token) {
		body, _ := json.Marshal(token.Claims)
		var mapped jwt.MapClaims
		_ = json.Unmarshal(body, &mapped)
		mapped["client_id"] = "development-agent"
		token.Claims = mapped
		if expiry, err := mapped.GetExpirationTime(); err == nil && expiry != nil {
			result.ExpiresAt = expiry.Unix()
		}
	})
	if err != nil {
		return "", result, errors.New("development signing failed")
	}
	v, err := auth.NewVerifier(ctx, &keys, e.config.Policy)
	if err != nil {
		return "", result, errors.New("development verifier unavailable")
	}
	p, err := v.Verify(ctx, token)
	if err != nil || !fixedPrincipal(p) {
		return "", result, errors.New("renewed credential failed actual Mechanize verification")
	}
	result.ClientID = p.ClientID
	return token, result, nil
}
func fixedPrincipal(p auth.Principal) bool {
	return p.Subject == fmt.Sprintf("local-uid-%d", os.Getuid()) && p.ClientID == "development-agent" && p.Tenant == "" && len(p.Scopes) == 2 && p.HasScope("desktop:observe") && p.HasScope("desktop:control")
}
func publish(ctx context.Context, e enrollment, token string) error {
	if err := e.unchanged(); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(e.tokenPath), ".stdio-renew-*")
	if err != nil {
		return errors.New("credential publication unavailable")
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.WriteString(token); err != nil {
		return errors.New("credential publication failed")
	}
	if err = f.Sync(); err != nil {
		return errors.New("credential publication failed")
	}
	if err = f.Close(); err != nil {
		return errors.New("credential publication failed")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = e.unchanged(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), e.tokenPath); err != nil {
		return errors.New("credential publication failed")
	}
	return nil
}

// Renew is the explicit operator path; old claims never supply issued authority.
func Renew(ctx context.Context, path string, apply bool) (Report, error) {
	e, err := readEnrollment(ctx, path)
	if err != nil {
		return Report{}, err
	}
	if apply {
		release, err := Lock(filepath.Dir(e.tokenPath))
		if err != nil {
			return Report{}, err
		}
		defer release()
		fresh, err := readEnrollment(ctx, path)
		if err != nil || !bytes.Equal(e.raw, fresh.raw) || !bytes.Equal(e.key, fresh.key) {
			return Report{}, errors.New("enrollment changed during renewal")
		}
		e = fresh
	}
	token, result, err := mint(ctx, e)
	if err != nil || !apply {
		return result, err
	}
	if err = publish(ctx, e, token); err != nil {
		return result, err
	}
	result.Renewed = true
	return result, nil
}

// Load renews eligible enrollment before dispatch, never after an HTTP failure.
// handled=false preserves all other identity providers' existing loading paths.
func Load(ctx context.Context, path string) (token string, handled bool, err error) {
	_, c, err := readConfig(path)
	if err != nil {
		// The established loader owns malformed or noneligible resources.
		// This path must not change other providers or mint from unsafe files.
		return "", false, nil
	}
	if !eligible(c) {
		return "", false, nil
	}
	e, err := readEnrollment(ctx, path)
	if err != nil {
		return "", true, err
	}
	token, expiry, err := inspect(ctx, e)
	if err != nil {
		return "", true, err
	}
	if time.Until(expiry) > RenewalWindow {
		return token, true, nil
	}
	release, err := Lock(filepath.Dir(e.tokenPath))
	if err != nil {
		// Another cooperating process may be renewing. A still-valid verified
		// token can serve this request; an expired one never crosses transport.
		if errors.Is(err, ErrRenewalActive) && time.Now().Before(expiry) {
			return token, true, ctx.Err()
		}
		return "", true, err
	}
	defer release()
	fresh, err := readEnrollment(ctx, path)
	if err != nil || !bytes.Equal(e.raw, fresh.raw) || !bytes.Equal(e.key, fresh.key) {
		return "", true, errors.New("enrollment changed during renewal")
	}
	token, expiry, err = inspect(ctx, fresh)
	if err != nil {
		return "", true, err
	}
	if time.Until(expiry) > RenewalWindow {
		return token, true, nil
	}
	token, _, err = mint(ctx, fresh)
	if err != nil {
		return "", true, err
	}
	if err = publish(ctx, fresh, token); err != nil {
		return "", true, err
	}
	return token, true, nil
}

// expirationOnly recognizes the exact Scy/JWT temporal failure tree. Signature,
// not-before, malformed claims and every other error remain fatal.
func expirationOnly(err error) bool {
	if !errors.Is(err, jwt.ErrTokenExpired) {
		return false
	}
	var allowed func(error) bool
	allowed = func(e error) bool {
		if many, ok := e.(interface{ Unwrap() []error }); ok {
			for _, child := range many.Unwrap() {
				if !allowed(child) {
					return false
				}
			}
			return true
		}
		if one, ok := e.(interface{ Unwrap() error }); ok {
			return allowed(one.Unwrap())
		}
		return e == jwt.ErrTokenExpired || e == jwt.ErrTokenInvalidClaims
	}
	return allowed(err)
}
func inspect(ctx context.Context, e enrollment) (string, time.Time, error) {
	denied := func() (string, time.Time, error) {
		return "", time.Time{}, errors.New("existing local development credential is ineligible")
	}
	if err := ctx.Err(); err != nil {
		return "", time.Time{}, err
	}
	secret, err := scy.New().Load(ctx, &scy.Resource{URL: e.tokenPath, Data: e.old})
	if err != nil {
		return denied()
	}
	raw := strings.TrimSpace(secret.String())
	if len(raw) < 32 || len(raw) > 32768 || strings.ContainsAny(raw, "\r\n") {
		return denied()
	}
	keys := e.keys()
	s := verifier.New(&keys)
	if err = s.Init(ctx); err != nil {
		return denied()
	}
	token, verifyErr := s.Validate(ctx, raw)
	if verifyErr != nil {
		if !expirationOnly(verifyErr) {
			return denied()
		}
		// Scy verified the current signature; only expiration failed. Parsing
		// retrieves fixed-identity checks and expiry, never minting authority.
		token, _, err = new(jwt.Parser).ParseUnverified(raw, jwt.MapClaims{})
		if err != nil {
			return denied()
		}
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || token.Method.Alg() != "HS256" {
		return denied()
	}
	issuer, err := claims.GetIssuer()
	if err != nil || issuer != e.config.Policy.Issuer {
		return denied()
	}
	aud, err := claims.GetAudience()
	if err != nil || len(aud) != 1 || aud[0] != e.config.Policy.Audience {
		return denied()
	}
	subject, err := claims.GetSubject()
	if err != nil || subject != fmt.Sprintf("local-uid-%d", os.Getuid()) || claims["client_id"] != "development-agent" {
		return denied()
	}
	scope, ok := claims["scope"].(string)
	if !ok {
		return denied()
	}
	p, err := auth.NewPrincipal(issuer, "", subject, strings.Fields(scope))
	if err != nil {
		return denied()
	}
	p.ClientID = "development-agent"
	if !fixedPrincipal(p) {
		return denied()
	}
	now := time.Now()
	nbf, err := claims.GetNotBefore()
	if err != nil || nbf != nil && now.Before(nbf.Time) {
		return denied()
	}
	iat, err := claims.GetIssuedAt()
	if err != nil || iat == nil || now.Before(iat.Time) {
		return denied()
	}
	expiry, err := claims.GetExpirationTime()
	if err != nil || expiry == nil || !expiry.Time.After(iat.Time) {
		return denied()
	}
	if verifyErr == nil {
		v, err := auth.NewVerifier(ctx, &keys, e.config.Policy)
		if err != nil {
			return denied()
		}
		actual, err := v.Verify(ctx, raw)
		if err != nil || !fixedPrincipal(actual) {
			return denied()
		}
	}
	return raw, expiry.Time, nil
}
