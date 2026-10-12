package vault

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/scy/kms"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxCredentialBytes = 64 * 1024

// Store owns only encrypted files, not database metadata. Construct from trusted
// host configuration; root/version/cipher cannot come from MCP or DSL inputs.
type Store struct {
	root    *os.Root
	path    string
	version string
	cipher  kms.Cipher
}
type envelope struct {
	Version    string `json:"version"`
	Ciphertext []byte `json:"ciphertext"`
	Namespace  string `json:"namespace,omitempty"`
	Tag        []byte `json:"tag,omitempty"`
}
type payload struct {
	Username     []byte `json:"username"`
	Password     []byte `json:"password"`
	Origin       string `json:"origin,omitempty"`
	AccountAlias string `json:"accountAlias,omitempty"`
}

func NewStore(root, version string, cipher kms.Cipher) (*Store, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !outsideGit(root) || version == "" || len(version) > 128 || cipher == nil {
		return nil, ErrUnavailable
	}
	// Reject symlinks at every component before opening the anchored root.
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Clean(root), current), string(filepath.Separator)) {
		current = filepath.Join(current, part)
		if err := os.Mkdir(current, 0700); err != nil && !os.IsExist(err) {
			return nil, ErrUnavailable
		}
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrUnavailable
		}
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode().Perm()&0077 != 0 {
		return nil, ErrUnavailable
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, ErrUnavailable
	}
	actual, err := r.Stat(".")
	if err != nil || !os.SameFile(info, actual) {
		r.Close()
		return nil, ErrUnavailable
	}
	if !outsideGit(root) {
		r.Close()
		return nil, ErrUnavailable
	}
	return &Store{root: r, path: root, version: version, cipher: cipher}, nil
}
func (s *Store) Close() error { return s.root.Close() }
func scoped(ctx context.Context, t Target) (string, string, error) {
	p, err := auth.FromContext(ctx)
	if err != nil {
		return "", "", err
	}
	if err = t.Validate(); err != nil {
		return "", "", err
	}
	return p.Namespace, identifier(p.Namespace, t), nil
}
func (s *Store) read(ctx context.Context, t Target) (Credentials, error) {
	return s.readRevision(ctx, t, "")
}

// readRevision checks and decrypts the same opened ciphertext bytes. A separate
// metadata lookup followed by a second open would not bind the consumed values.
func (s *Store) readRevision(ctx context.Context, t Target, revision string) (Credentials, error) {
	if !outsideGit(s.path) {
		return Credentials{}, ErrUnavailable
	}
	ns, id, err := scoped(ctx, t)
	if err != nil {
		return Credentials{}, err
	}
	f, err := s.root.OpenFile(id+".enc", os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return Credentials{}, ErrMissing
	}
	if err != nil {
		return Credentials{}, ErrUnavailable
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !privateVaultFile(info) || info.Size() > 2*maxCredentialBytes {
		return Credentials{}, ErrUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(f, 2*maxCredentialBytes))
	if err != nil {
		return Credentials{}, ErrUnavailable
	}
	if revision != "" {
		digest := sha256.Sum256(b)
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(digest[:])), []byte(revision)) != 1 {
			return Credentials{}, ErrConflict
		}
	}
	var e envelope
	if json.Unmarshal(b, &e) != nil || e.Version != s.version {
		return Credentials{}, ErrUnavailable
	}
	if revision != "" && (e.Namespace != ns || len(e.Tag) != 32) {
		return Credentials{}, ErrUnavailable
	}
	if (e.Namespace != "" || len(e.Tag) != 0) && (e.Namespace != ns || s.verifyEnvelope(ctx, id, e) != nil) {
		return Credentials{}, ErrUnavailable
	}
	plain, err := s.cipher.Decrypt(ctx, &kms.Key{Raw: e.Version, Path: ns + ":" + id}, e.Ciphertext)
	if err != nil {
		return Credentials{}, ErrUnavailable
	}
	defer clear(plain)
	var value payload
	if json.Unmarshal(plain, &value) != nil || len(value.Username) == 0 || len(value.Password) == 0 || len(value.Username)+len(value.Password) > maxCredentialBytes {
		clear(value.Username)
		clear(value.Password)
		return Credentials{}, ErrUnavailable
	}
	if (value.Origin != "" || value.AccountAlias != "") && (value.Origin != t.Origin || value.AccountAlias != t.Account) {
		clear(value.Username)
		clear(value.Password)
		return Credentials{}, ErrUnavailable
	}
	if revision != "" && (value.Origin != t.Origin || value.AccountAlias != t.Account) {
		clear(value.Username)
		clear(value.Password)
		return Credentials{}, ErrUnavailable
	}
	return Credentials{username: value.Username, password: value.Password}, nil
}
func (s *Store) Lookup(ctx context.Context, t Target) (Reference, error) {
	c, err := s.read(ctx, t)
	if err != nil {
		return Reference{}, err
	}
	clear(c.username)
	clear(c.password)
	p, _ := auth.FromContext(ctx)
	return Reference{ResourceURL: reference(p.Namespace, t)}, nil
}

// put is reachable only through Manager.Submit's verified native-human boundary.
func (s *Store) put(ctx context.Context, t Target, username, password []byte) (Reference, error) {
	if !outsideGit(s.path) {
		return Reference{}, ErrUnavailable
	}
	ns, id, err := scoped(ctx, t)
	if err != nil {
		return Reference{}, err
	}
	if len(username) == 0 || len(password) == 0 || len(username)+len(password) > maxCredentialBytes {
		return Reference{}, ErrScope
	}
	plain, err := json.Marshal(payload{Username: username, Password: password, Origin: t.Origin, AccountAlias: t.Account})
	if err != nil {
		return Reference{}, ErrUnavailable
	}
	defer clear(plain)
	b, err := s.cipher.Encrypt(ctx, &kms.Key{Raw: s.version, Path: ns + ":" + id}, plain)
	if err != nil {
		return Reference{}, ErrUnavailable
	}
	sealed := envelope{Version: s.version, Ciphertext: b, Namespace: ns}
	signer, ok := s.cipher.(interface {
		EnvelopeTag(context.Context, string, string, string, []byte) ([]byte, error)
	})
	if !ok {
		return Reference{}, ErrUnavailable
	}
	sealed.Tag, err = signer.EnvelopeTag(ctx, s.version, ns, id, b)
	if err != nil {
		return Reference{}, ErrUnavailable
	}
	encoded, err := json.Marshal(sealed)
	if err != nil || len(encoded) > 2*maxCredentialBytes {
		return Reference{}, ErrUnavailable
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return Reference{}, ErrUnavailable
	}
	temp := "." + hex.EncodeToString(random[:]) + ".tmp"
	f, err := s.root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return Reference{}, ErrUnavailable
	}
	defer s.root.Remove(temp)
	_, err = f.Write(encoded)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return Reference{}, ErrUnavailable
	}
	if err = ctx.Err(); err != nil {
		return Reference{}, err
	}
	if err = s.root.Rename(temp, id+".enc"); err != nil {
		return Reference{}, ErrUnavailable
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return Reference{}, ErrUnavailable
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return Reference{}, ErrUnavailable
	}
	return Reference{ResourceURL: reference(ns, t)}, nil
}

// Consume resolves an exact enrolled reference only after a trusted backend has
// freshly verified the original target/document. It never returns credential
// bytes. The caller must neither retain nor log callback buffers.
func (s *Store) Consume(ctx context.Context, t Target, ref Reference, consume func(Credentials) error) error {
	p, err := auth.FromContext(ctx)
	if err != nil {
		return err
	}
	if t.Validate() != nil || ref.ResourceURL != reference(p.Namespace, t) || consume == nil {
		return ErrScope
	}
	c, err := s.read(ctx, t)
	if err != nil {
		return err
	}
	defer clear(c.username)
	defer clear(c.password)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := consume(c); err != nil {
		return ErrUnavailable
	}
	return nil
}
