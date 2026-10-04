// Package artifact stores authenticated, encrypted evidence bytes. Product
// metadata and checkpoint transactions remain exclusively owned by Datly.
package artifact

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/viant/mechanize/auth"
	"io"
	"mime"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/viant/mechanize/data"
	"golang.org/x/sys/unix"
)

var (
	ErrCorrupt        = errors.New("artifact authentication or metadata verification failed")
	ErrLimit          = errors.New("artifact storage limit exceeded")
	ErrKeyUnavailable = errors.New("artifact key unavailable")
	safeID            = regexp.MustCompile(`^[a-f0-9]{32}$`)
)

// KeyResolver is trusted application configuration, never a request parameter.
// Implementations must return a fresh copy of the configured version's AES-256
// key via Scy. The store clears the returned buffer after creating its AEAD.
type KeyResolver interface {
	Resolve(context.Context, string) ([]byte, error)
}

type Config struct {
	Root                string
	SourceKeyReference  string
	Keys                KeyResolver
	MaxBytes            int64
	NamespaceQuotaBytes int64
}

type Store struct {
	config Config
	root   *os.Root
}

type payload struct {
	Reference data.ArtifactReference `json:"reference"`
	Bytes     []byte                 `json:"bytes"`
}

// New creates a private trusted storage root. It denies symlinks in every root
// path component. No request may select Root, Keys, or SourceKeyReference.
func New(config Config) (*Store, error) {
	if config.Root == "" || config.Keys == nil || config.SourceKeyReference == "" || len(config.SourceKeyReference) > 256 {
		return nil, errors.New("trusted artifact root and key configuration required")
	}
	if config.MaxBytes <= 0 || config.MaxBytes > 1<<30 || config.NamespaceQuotaBytes <= 0 {
		return nil, errors.New("bounded artifact byte and namespace quota required")
	}
	absolute, err := filepath.Abs(config.Root)
	if err != nil {
		return nil, err
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(absolute, current), string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if os.IsNotExist(statErr) {
			if err = os.Mkdir(current, 0700); err != nil && !os.IsExist(err) {
				return nil, err
			}
			info, statErr = os.Lstat(current)
		}
		if statErr != nil {
			return nil, statErr
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("artifact root must contain only real directories")
		}
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("artifact root must be private (0700)")
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, err
	}
	actual, err := root.Stat(".")
	if err != nil || !os.SameFile(info, actual) {
		root.Close()
		return nil, errors.New("artifact root changed during open")
	}
	config.Root = absolute
	return &Store{config: config, root: root}, nil
}
func (s *Store) Close() error { return s.root.Close() }

func (s *Store) namespace(ctx context.Context, namespace string, create bool) (*os.Root, error) {
	principal, err := auth.FromContext(ctx)
	if err != nil || principal.Namespace != namespace {
		return nil, auth.ErrUnauthorized
	}
	if _, err := data.RequireScope(ctx, namespace); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if create {
		if err := s.root.Mkdir(namespace, 0700); err != nil && !os.IsExist(err) {
			return nil, err
		}
		parent, err := s.root.Open(".")
		if err != nil {
			return nil, err
		}
		err = parent.Sync()
		closeErr := parent.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	before, err := s.root.Lstat(namespace)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private artifact namespace directory required")
	}
	root, err := s.root.OpenRoot(namespace)
	if err != nil {
		return nil, err
	}
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		root.Close()
		return nil, errors.New("artifact namespace changed during open")
	}
	return root, nil
}
func (s *Store) aead(ctx context.Context, reference string) (cipher.AEAD, error) {
	key, err := s.config.Keys.Resolve(ctx, reference)
	if err != nil {
		return nil, fmt.Errorf("%w", ErrKeyUnavailable)
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	if len(key) != 32 {
		return nil, ErrKeyUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	return cipher.NewGCM(block)
}
func associated(namespace, id, key string) []byte {
	b, _ := json.Marshal([]string{"mechanize-artifact-v1", namespace, id, key})
	return b
}
func identifier() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func checkReference(ref data.ArtifactReference, max int64) error {
	if !safeID.MatchString(ref.ID) || ref.SizeBytes < 0 || int64(ref.SizeBytes) > max || len(ref.ContentHash) != 64 || ref.KeyReference == "" || len(ref.KeyReference) > 256 || len(ref.MediaType) > 256 {
		return ErrCorrupt
	}
	digest, err := hex.DecodeString(ref.ContentHash)
	if err != nil || len(digest) != 32 {
		return ErrCorrupt
	}
	return nil
}

// Put requires already-redacted/allowlisted evidence. It cannot determine image
// redaction coverage. All bytes and their descriptive metadata are encrypted.
// The returned reference is ready for the Datly publication transaction only
// after Verify succeeds. Files published without a DB reference are harmless
// orphans; retention/GC must be coordinated with Datly checkpoint reachability.
func (s *Store) Put(ctx context.Context, namespace, mediaType string, source io.Reader) (data.ArtifactReference, error) {
	return s.put(ctx, namespace, "", s.config.SourceKeyReference, mediaType, source)
}

// put shares the immutable encrypted write path. An empty ID is the legacy Put
// path; reserved callers already committed their explicit identity/key version.
func (s *Store) put(ctx context.Context, namespace, id, keyReference, mediaType string, source io.Reader) (data.ArtifactReference, error) {
	var zero data.ArtifactReference
	reserved := id != ""
	if source == nil || len(mediaType) > 256 {
		return zero, errors.New("bounded artifact source and media type required")
	}
	parsed, _, err := mime.ParseMediaType(mediaType)
	if err != nil || parsed == "" {
		return zero, errors.New("valid media type required")
	}
	root, err := s.namespace(ctx, namespace, true)
	if err != nil {
		return zero, err
	}
	defer root.Close()
	aead, err := s.aead(ctx, keyReference)
	if err != nil {
		return zero, err
	}
	bytes, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, r: source}, s.config.MaxBytes+1))
	defer clear(bytes)
	if err != nil {
		return zero, err
	}
	if int64(len(bytes)) > s.config.MaxBytes {
		return zero, ErrLimit
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	if id == "" {
		id, err = identifier()
		if err != nil {
			return zero, err
		}
	}
	sum := sha256.Sum256(bytes)
	ref := data.ArtifactReference{ID: id, ContentHash: hex.EncodeToString(sum[:]), SizeBytes: len(bytes), MediaType: mediaType, KeyReference: keyReference}
	plaintext, err := json.Marshal(payload{Reference: ref, Bytes: bytes})
	defer clear(plaintext)
	if err != nil {
		return zero, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return zero, err
	}
	encrypted := append([]byte("MAE1"), nonce...)
	encrypted = aead.Seal(encrypted, nonce, plaintext, associated(namespace, id, ref.KeyReference))
	// Serialize quota allocation across Store instances and processes, not just
	// goroutines. Lock is scoped to an already verified directory handle.
	directory, err := root.Open(".")
	if err != nil {
		return zero, err
	}
	defer directory.Close()
	if err = lockDirectory(ctx, directory); err != nil {
		return zero, err
	}
	defer unix.Flock(int(directory.Fd()), unix.LOCK_UN)
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	if reserved {
		if _, err = root.Lstat(id); err == nil {
			return zero, ErrExists
		} else if !os.IsNotExist(err) {
			return zero, err
		}
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return zero, err
	}
	var total int64
	for _, entry := range entries {
		info, statErr := root.Lstat(entry.Name())
		if statErr != nil {
			return zero, statErr
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return zero, errors.New("unexpected artifact namespace entry")
		}
		if info.Size() > s.config.NamespaceQuotaBytes-total {
			return zero, ErrLimit
		}
		total += info.Size()
	}
	if int64(len(encrypted)) > s.config.NamespaceQuotaBytes-total {
		return zero, ErrLimit
	}
	temp := ".stage-" + id
	file, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		if reserved && os.IsExist(err) {
			return zero, ErrExists
		}
		return zero, err
	}
	defer root.Remove(temp)
	if _, err = file.Write(encrypted); err != nil {
		file.Close()
		return zero, err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return zero, err
	}
	if err = file.Close(); err != nil {
		return zero, err
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	// Link publishes atomically without replacing any existing immutable file.
	// Both names are on the same filesystem. Flush namespace after publication.
	if err = root.Link(temp, id); err != nil {
		if reserved && os.IsExist(err) {
			return zero, ErrExists
		}
		return zero, err
	}
	// A committed reserved identity is recoverable even if post-link durability
	// acknowledgement fails. Never remove the immutable final link on error.
	linked := zero
	if reserved {
		linked = ref
	}
	if err = directory.Sync(); err != nil {
		return linked, err
	}
	if err = root.Remove(temp); err != nil {
		return linked, err
	}
	if err = directory.Sync(); err != nil {
		return linked, err
	}
	return ref, nil
}

// Read authenticates scope, bytes, key version and all reference fields before
// releasing plaintext. It also serves explicit user-scoped export operations;
// callers enforce the configured redacted-export policy before distribution.
func (s *Store) Read(ctx context.Context, namespace string, ref data.ArtifactReference) ([]byte, error) {
	root, err := s.namespace(ctx, namespace, false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err = checkReference(ref, s.config.MaxBytes); err != nil {
		return nil, err
	}
	info, err := root.Lstat(ref.ID)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrCorrupt
	}
	// JSON base64 overhead plus bounded metadata and GCM/header overhead.
	maximum := s.config.MaxBytes*2 + 4096
	if info.Size() > maximum || info.Size() < 32 {
		return nil, ErrCorrupt
	}
	file, err := root.OpenFile(ref.ID, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, actual) {
		return nil, ErrCorrupt
	}
	encrypted, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, r: file}, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(encrypted)) > maximum || len(encrypted) < 32 || string(encrypted[:4]) != "MAE1" {
		return nil, ErrCorrupt
	}
	aead, err := s.aead(ctx, ref.KeyReference)
	if err != nil {
		return nil, err
	}
	nonceEnd := 4 + aead.NonceSize()
	if len(encrypted) < nonceEnd+aead.Overhead() {
		return nil, ErrCorrupt
	}
	plain, err := aead.Open(nil, encrypted[4:nonceEnd], encrypted[nonceEnd:], associated(namespace, ref.ID, ref.KeyReference))
	if err != nil {
		return nil, ErrCorrupt
	}
	var decoded payload
	if err = json.Unmarshal(plain, &decoded); err != nil || decoded.Reference != ref || len(decoded.Bytes) != ref.SizeBytes {
		return nil, ErrCorrupt
	}
	sum := sha256.Sum256(decoded.Bytes)
	if hex.EncodeToString(sum[:]) != ref.ContentHash {
		return nil, ErrCorrupt
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return decoded.Bytes, nil
}

// Verify is the trusted Builder.Options.VerifyArtifact callback. It verifies
// immutable file bytes rather than trusting a database row or caller manifest.
func (s *Store) Verify(ctx context.Context, namespace string, ref data.ArtifactReference) error {
	_, err := s.Read(ctx, namespace, ref)
	return err
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.r.Read(b)
	if cancel := r.ctx.Err(); cancel != nil {
		return n, cancel
	}
	return n, err
}

func lockDirectory(ctx context.Context, directory *os.File) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := unix.Flock(int(directory.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
			return err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
