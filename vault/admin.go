package vault

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"github.com/viant/mechanize/auth"
	"golang.org/x/sys/unix"
)

var ErrConflict = errors.New("vault entry exists or revision changed")
var ErrBusy = errors.New("vault administration busy")

// EntryMetadata exposes only an opaque reference and a ciphertext revision.
// It contains no username, password, plaintext digest or secret-derived label.
type EntryMetadata struct {
	Reference Reference `json:"reference"`
	Revision  string    `json:"revision"`
}

func (s *Store) writeLock(ctx context.Context, action func() error) error {
	if !outsideGit(s.path) {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := s.root.OpenFile(".vault-write.lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return ErrUnavailable
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !privateVaultFile(info) {
		return ErrUnavailable
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return ErrBusy
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	if err = ctx.Err(); err != nil {
		return err
	}
	return action()
}

func (s *Store) metadata(ctx context.Context, target Target) (EntryMetadata, error) {
	ref, err := s.Lookup(ctx, target) // Validate authenticated ciphertext; values remain local.
	if err != nil {
		return EntryMetadata{}, err
	}
	_, id, err := scoped(ctx, target)
	if err != nil {
		return EntryMetadata{}, err
	}
	f, err := s.root.OpenFile(id+".enc", os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return EntryMetadata{}, ErrUnavailable
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !privateVaultFile(info) {
		return EntryMetadata{}, ErrUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(f, 2*maxCredentialBytes+1))
	if err != nil || len(b) > 2*maxCredentialBytes {
		return EntryMetadata{}, ErrUnavailable
	}
	digest := sha256.Sum256(b)
	return EntryMetadata{Reference: ref, Revision: hex.EncodeToString(digest[:])}, nil
}

func (s *Store) Metadata(ctx context.Context, target Target) (EntryMetadata, error) {
	if _, _, err := scoped(ctx, target); err != nil {
		return EntryMetadata{}, err
	}
	var result EntryMetadata
	err := s.writeLock(ctx, func() error { var err error; result, err = s.metadata(ctx, target); return err })
	return result, err
}

func nativeAdmin(ctx context.Context, target Target) error {
	if !auth.NativeHuman(ctx) {
		return auth.ErrUnauthorized
	}
	_, _, err := scoped(ctx, target)
	return err
}

// Create, Update and Delete are native-human-only operations, never MCP secret
// setters. The trusted UI must independently qualify secure capture suppression.
func (s *Store) Create(ctx context.Context, target Target, username, password []byte) (Reference, error) {
	defer clear(username)
	defer clear(password)
	if err := nativeAdmin(ctx, target); err != nil {
		return Reference{}, err
	}
	var result Reference
	err := s.writeLock(ctx, func() error {
		_, err := s.Lookup(ctx, target)
		if err == nil {
			return ErrConflict
		}
		if !errors.Is(err, ErrMissing) {
			return err
		}
		result, err = s.put(ctx, target, username, password)
		return err
	})
	return result, err
}

func (s *Store) Update(ctx context.Context, target Target, revision string, username, password []byte) (Reference, error) {
	defer clear(username)
	defer clear(password)
	if err := nativeAdmin(ctx, target); err != nil {
		return Reference{}, err
	}
	var result Reference
	err := s.writeLock(ctx, func() error {
		meta, err := s.metadata(ctx, target)
		if err != nil {
			return err
		}
		if len(revision) != 64 || subtle.ConstantTimeCompare([]byte(meta.Revision), []byte(revision)) != 1 {
			return ErrConflict
		}
		result, err = s.put(ctx, target, username, password)
		return err
	})
	return result, err
}

func (s *Store) Delete(ctx context.Context, target Target, revision string) error {
	if err := nativeAdmin(ctx, target); err != nil {
		return err
	}
	return s.writeLock(ctx, func() error {
		meta, err := s.metadata(ctx, target)
		if err != nil {
			return err
		}
		if len(revision) != 64 || subtle.ConstantTimeCompare([]byte(meta.Revision), []byte(revision)) != 1 {
			return ErrConflict
		}
		_, id, err := scoped(ctx, target)
		if err != nil {
			return err
		}
		if err = s.root.Remove(id + ".enc"); err != nil {
			return ErrUnavailable
		}
		dir, err := s.root.Open(".")
		if err != nil {
			return ErrUnavailable
		}
		defer dir.Close()
		if err = dir.Sync(); err != nil {
			return ErrUnavailable
		}
		return nil
	})
}
