package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"os"

	"github.com/viant/mechanize/data"
	"golang.org/x/sys/unix"
)

var ErrExists = errors.New("immutable reserved artifact already exists; inspect before reconciliation")

// PutReserved uses an ID/key version from a committed trusted host reservation,
// never MCP request strings. It does not replace/adopt existing bytes or publish
// database metadata. Errors after the atomic link retain recovery by this ID/key.
func (s *Store) PutReserved(ctx context.Context, namespace, id, keyReference, mediaType string, source io.Reader) (data.ArtifactReference, error) {
	if !safeID.MatchString(id) || keyReference == "" || len(keyReference) > 256 {
		return data.ArtifactReference{}, ErrCorrupt
	}
	return s.put(ctx, namespace, id, keyReference, mediaType, source)
}

// InspectReserved authenticates one known reserved ID and explicit allowed key
// version without requiring metadata publication. It never scans directories or
// guesses a key version. Returned plaintext belongs to the trusted host, which
// must clear it after reconciliation; this method is not an export authorization.
func (s *Store) InspectReserved(ctx context.Context, namespace, id, keyReference string) (data.ArtifactReference, []byte, error) {
	var zero data.ArtifactReference
	if !safeID.MatchString(id) || keyReference == "" || len(keyReference) > 256 {
		return zero, nil, ErrCorrupt
	}
	root, err := s.namespace(ctx, namespace, false)
	if err != nil {
		return zero, nil, err
	}
	defer root.Close()
	info, err := root.Lstat(id)
	if err != nil {
		return zero, nil, err
	}
	maximum := s.config.MaxBytes*2 + 4096
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 32 || info.Size() > maximum {
		return zero, nil, ErrCorrupt
	}
	file, err := root.OpenFile(id, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return zero, nil, err
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil {
		return zero, nil, err
	}
	if !os.SameFile(info, actual) {
		return zero, nil, ErrCorrupt
	}
	encrypted, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, r: file}, maximum+1))
	defer clear(encrypted)
	if err != nil {
		return zero, nil, err
	}
	if int64(len(encrypted)) > maximum || len(encrypted) < 32 || string(encrypted[:4]) != "MAE1" {
		return zero, nil, ErrCorrupt
	}
	aead, err := s.aead(ctx, keyReference)
	if err != nil {
		return zero, nil, err
	}
	nonceEnd := 4 + aead.NonceSize()
	if len(encrypted) < nonceEnd+aead.Overhead() {
		return zero, nil, ErrCorrupt
	}
	plain, err := aead.Open(nil, encrypted[4:nonceEnd], encrypted[nonceEnd:], associated(namespace, id, keyReference))
	if err != nil {
		return zero, nil, ErrCorrupt
	}
	defer clear(plain)
	var decoded payload
	success := false
	defer func() {
		if !success {
			clear(decoded.Bytes)
		}
	}()
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&decoded); err != nil {
		return zero, nil, ErrCorrupt
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return zero, nil, ErrCorrupt
	}
	ref := decoded.Reference
	if ref.ID != id || ref.KeyReference != keyReference || checkReference(ref, s.config.MaxBytes) != nil || len(decoded.Bytes) != ref.SizeBytes {
		return zero, nil, ErrCorrupt
	}
	parsed, _, err := mime.ParseMediaType(ref.MediaType)
	if err != nil || parsed == "" {
		return zero, nil, ErrCorrupt
	}
	sum := sha256.Sum256(decoded.Bytes)
	if hex.EncodeToString(sum[:]) != ref.ContentHash {
		return zero, nil, ErrCorrupt
	}
	if err = ctx.Err(); err != nil {
		return zero, nil, err
	}
	success = true
	return ref, decoded.Bytes, nil
}
