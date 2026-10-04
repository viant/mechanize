// Package vault keeps credential bytes on the authenticated local path. Only
// opaque resource references may be exposed to agents or workflow scripts.
package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var (
	ErrScope       = errors.New("vault target is not an exact HTTPS origin and account alias")
	ErrUnavailable = errors.New("vault key or encrypted credential unavailable")
	ErrMissing     = errors.New("vault credential missing")
	ErrPending     = errors.New("credential entry pending in native Vault")
	ErrStale       = errors.New("vault request expired or browser document changed")
)

// Target comes from a fresh browser observation and a workflow's opaque account
// alias. Account is not a username. No path, query, userinfo or wildcard is legal.
type Target struct {
	Origin  string
	Account string
}

func (t Target) Validate() error {
	u, err := url.Parse(t.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Opaque != "" || u.Host != strings.ToLower(u.Host) || u.String() != t.Origin || strings.HasSuffix(u.Host, ":443") || strings.HasSuffix(u.Hostname(), ".") {
		return ErrScope
	}
	if len(t.Account) < 1 || len(t.Account) > 128 {
		return ErrScope
	}
	for _, c := range t.Account {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return ErrScope
		}
	}
	return nil
}

func identifier(namespace string, t Target) string {
	b, _ := json.Marshal([]string{"mechanize.vault.v1", namespace, t.Origin, t.Account})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func reference(namespace string, t Target) string {
	return "mechanize-vault://credential/" + namespace + "/" + identifier(namespace, t)
}

// Reference is the complete public result: username and password are absent.
type Reference struct {
	ResourceURL string `json:"resourceURL"`
}

// Credentials is intentionally not serializable. The local backend can consume
// bytes synchronously; buffers are cleared immediately after its callback.
type Credentials struct{ username, password []byte }

func (Credentials) MarshalJSON() ([]byte, error) {
	return nil, errors.New("vault credentials cannot be serialized")
}
func (Credentials) String() string   { return "[vault credential withheld]" }
func (Credentials) GoString() string { return "[vault credential withheld]" }
func (Credentials) Format(state fmt.State, verb rune) {
	state.Write([]byte("[vault credential withheld]"))
}
func (c Credentials) WithBytes(consume func(username, password []byte) error) error {
	return consume(c.username, c.password)
}
