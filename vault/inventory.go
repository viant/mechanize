package vault

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/viant/mechanize/auth"
	"github.com/viant/scy/kms"
	"golang.org/x/sys/unix"
)

// Native inventory never includes usernames, passwords or plaintext digests.
// Target routing is encrypted at rest and returned only to the signed human UI.
type InventoryEntry struct {
	Origin       string    `json:"origin"`
	AccountAlias string    `json:"accountAlias"`
	Reference    Reference `json:"reference"`
	Revision     string    `json:"revision"`
}

func (s *Store) verifyEnvelope(ctx context.Context, id string, e envelope) error {
	if e.Version != s.version || !nativeRevision(e.Namespace) || !nativeRevision(id) || len(e.Tag) != 32 {
		return ErrUnavailable
	}
	signer, ok := s.cipher.(interface {
		EnvelopeTag(context.Context, string, string, string, []byte) ([]byte, error)
	})
	if !ok {
		return ErrUnavailable
	}
	tag, err := signer.EnvelopeTag(ctx, e.Version, e.Namespace, id, e.Ciphertext)
	if err != nil || !hmac.Equal(tag, e.Tag) {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) Inventory(ctx context.Context) ([]InventoryEntry, error) {
	if !auth.NativeHuman(ctx) {
		return nil, auth.ErrUnauthorized
	}
	p, _ := auth.FromContext(ctx)
	var result []InventoryEntry
	err := s.writeLock(ctx, func() error {
		dir, err := s.root.Open(".")
		if err != nil {
			return ErrUnavailable
		}
		defer dir.Close()
		files, err := dir.ReadDir(257)
		if err != nil && err != io.EOF {
			return ErrUnavailable
		}
		if len(files) > 256 {
			return ErrUnavailable
		}
		result = []InventoryEntry{}
		for _, file := range files {
			if ctx.Err() != nil {
				return ErrUnavailable
			}
			name := file.Name()
			if name == ".vault-write.lock" {
				continue
			}
			if !strings.HasSuffix(name, ".enc") || !nativeRevision(strings.TrimSuffix(name, ".enc")) {
				return ErrUnavailable
			}
			id := strings.TrimSuffix(name, ".enc")
			f, err := s.root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW, 0)
			if err != nil {
				return ErrUnavailable
			}
			info, err := f.Stat()
			if err != nil || !privateVaultFile(info) || info.Size() > 2*maxCredentialBytes {
				f.Close()
				return ErrUnavailable
			}
			data, err := io.ReadAll(io.LimitReader(f, 2*maxCredentialBytes+1))
			f.Close()
			if err != nil || len(data) > 2*maxCredentialBytes {
				return ErrUnavailable
			}
			var e envelope
			if json.Unmarshal(data, &e) != nil || s.verifyEnvelope(ctx, id, e) != nil {
				return ErrUnavailable
			}
			if e.Namespace != p.Namespace {
				continue
			} // Header verified; no foreign decryption.
			plain, err := s.cipher.Decrypt(ctx, &kms.Key{Raw: e.Version, Path: p.Namespace + ":" + id}, e.Ciphertext)
			if err != nil {
				return ErrUnavailable
			}
			var value payload
			err = json.Unmarshal(plain, &value)
			clear(plain)
			target := Target{Origin: value.Origin, Account: value.AccountAlias}
			valid := err == nil && target.Validate() == nil && identifier(p.Namespace, target) == id && len(value.Username) > 0 && len(value.Password) > 0 && len(value.Username)+len(value.Password) <= maxCredentialBytes
			clear(value.Username)
			clear(value.Password)
			if !valid {
				return ErrUnavailable
			}
			digest := sha256.Sum256(data)
			result = append(result, InventoryEntry{Origin: target.Origin, AccountAlias: target.Account, Reference: Reference{ResourceURL: reference(p.Namespace, target)}, Revision: hex.EncodeToString(digest[:])})
		}
		return nil
	})
	if err != nil {
		return nil, ErrUnavailable
	}
	return result, nil
}
