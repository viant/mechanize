package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"github.com/viant/mechanize/artifact"
	"github.com/viant/scy/kms"
	"io"
)

// Cipher implements Scy's KMS boundary with authenticated encryption. Keys are
// resolved through an enrolled ScyResolver (typically mechanize-keychain).
// kms.Key.Raw is a non-secret configured version; Path is authenticated scope.
// No default, inline key or URI-supplied key material is supported.
type Cipher struct{ Keys artifact.KeyResolver }

var _ kms.Cipher = (*Cipher)(nil)

// Authenticates routing without decrypting another namespace's credentials.
func (c *Cipher) EnvelopeTag(ctx context.Context, version, namespace, id string, encrypted []byte) ([]byte, error) {
	if c == nil || c.Keys == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	key, err := c.Keys.Resolve(ctx, version)
	defer clear(key)
	if err != nil || len(key) != 32 {
		return nil, ErrUnavailable
	}
	message, err := json.Marshal([]any{"mechanize.vault.envelope.v1", version, namespace, id, encrypted})
	if err != nil {
		return nil, ErrUnavailable
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil), nil
}

func (c *Cipher) Ready(ctx context.Context, version string) error {
	if c == nil || c.Keys == nil || version == "" || ctx.Err() != nil {
		return ErrUnavailable
	}
	key, err := c.Keys.Resolve(ctx, version)
	defer clear(key)
	if err != nil || len(key) != 32 || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

func (c *Cipher) aead(ctx context.Context, key *kms.Key) (cipher.AEAD, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c == nil || c.Keys == nil || key == nil || key.Raw == "" || key.Path == "" {
		return nil, ErrUnavailable
	}
	b, err := c.Keys.Resolve(ctx, key.Raw)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(b)
	if len(b) != 32 {
		return nil, ErrUnavailable
	}
	block, err := aes.NewCipher(b)
	if err != nil {
		return nil, ErrUnavailable
	}
	return cipher.NewGCM(block)
}
func (c *Cipher) Encrypt(ctx context.Context, key *kms.Key, plain []byte) ([]byte, error) {
	a, err := c.aead(ctx, key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrUnavailable
	}
	return a.Seal(nonce, nonce, plain, []byte(key.Path)), nil
}
func (c *Cipher) Decrypt(ctx context.Context, key *kms.Key, encrypted []byte) ([]byte, error) {
	a, err := c.aead(ctx, key)
	if err != nil {
		return nil, err
	}
	if len(encrypted) < a.NonceSize()+a.Overhead() {
		return nil, ErrUnavailable
	}
	b, err := a.Open(nil, encrypted[:a.NonceSize()], encrypted[a.NonceSize():], []byte(key.Path))
	if err != nil {
		return nil, ErrUnavailable
	}
	return b, nil
}
