package vault

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"

	"github.com/viant/mechanize/auth"
	"github.com/viant/scy/kms"
	"golang.org/x/sys/unix"
)

const recordDomain = "mechanize.vault.record.v1"
const recordMarker = ".record-store-v1"
const maxRecordFiles = 256
const maxRecordEnvelope = 2 * maxRecordPlaintext

// RecordStore is a private native-managed encrypted record store. The host must pass
// a separate private root outside Git, never the credential Store root or a
// subdirectory of it (the existing credential inventory rejects directories).
// It reuses the already enrolled cipher/version; it creates no master key and
// performs no automatic import. The explicit protected native import is separate.
// RecordDelivery is the sole consent-authorized, revision-
// bound credential consumer; there is no public plaintext lookup.
type RecordStore struct{ store *Store }
type RecordReference struct {
	ID string `json:"id"`
}
type RecordMetadata struct {
	Reference RecordReference `json:"reference"`
	Revision  string          `json:"revision"`
}
type recordEnvelope struct {
	Kind       string `json:"kind"`
	Version    string `json:"version"`
	Namespace  string `json:"namespace"`
	Ciphertext []byte `json:"ciphertext"`
	Tag        []byte `json:"tag"`
}

func NewRecordStore(root, version string, cipher kms.Cipher) (*RecordStore, error) {
	if _, ok := cipher.(interface {
		EnvelopeTag(context.Context, string, string, string, []byte) ([]byte, error)
	}); !ok {
		return nil, ErrUnavailable
	}
	s, err := NewStore(root, version, cipher)
	if err != nil {
		return nil, err
	}
	r := &RecordStore{store: s}
	// Reject legacy or unknown content before placing our exclusive format marker.
	dir, err := s.root.Open(".")
	if err != nil {
		s.Close()
		return nil, ErrUnavailable
	}
	entries, readErr := dir.ReadDir(2*maxRecordFiles + 4)
	dir.Close()
	if readErr != nil && readErr != io.EOF {
		s.Close()
		return nil, ErrUnavailable
	}
	hasMarker := false
	for _, e := range entries {
		if e.Name() == recordMarker {
			hasMarker = true
		}
	}
	if !hasMarker && len(entries) != 0 {
		s.Close()
		return nil, ErrUnavailable
	}
	if !hasMarker {
		f, e := s.root.OpenFile(recordMarker, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
		if e != nil {
			s.Close()
			return nil, ErrUnavailable
		}
		_, e = f.Write([]byte(recordDomain))
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			s.Close()
			return nil, ErrUnavailable
		}
		if e = r.sync(); e != nil {
			s.Close()
			return nil, e
		}
	}
	if _, err = r.ids(); err != nil {
		s.Close()
		return nil, err
	}
	return r, nil
}
func (r *RecordStore) Close() error { return r.store.Close() }
func recordAdmin(ctx context.Context) (string, error) {
	if !auth.NativeHuman(ctx) {
		return "", auth.ErrUnauthorized
	}
	p, err := auth.FromContext(ctx)
	return p.Namespace, err
}
func recordTagID(id string) string    { return recordDomain + ":" + id }
func recordPath(ns, id string) string { return recordDomain + ":" + ns + ":" + id }
func (r *RecordStore) tag(ctx context.Context, e recordEnvelope, id string) ([]byte, error) {
	signer, ok := r.store.cipher.(interface {
		EnvelopeTag(context.Context, string, string, string, []byte) ([]byte, error)
	})
	if !ok || e.Kind != recordDomain || e.Version != r.store.version || !nativeRevision(e.Namespace) || !nativeRevision(id) {
		return nil, ErrUnavailable
	}
	return signer.EnvelopeTag(ctx, e.Version, e.Namespace, recordTagID(id), e.Ciphertext)
}
func (r *RecordStore) readFile(name string, limit int) ([]byte, error) {
	f, err := r.store.root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if os.IsNotExist(err) {
		return nil, ErrMissing
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !privateVaultFile(info) || info.Size() > int64(limit) {
		return nil, ErrUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(b) > limit {
		return nil, ErrUnavailable
	}
	return b, nil
}
func (r *RecordStore) ids() ([]string, error) {
	// Recheck custody after opening, including chmod and path replacement.
	info, err := r.store.root.Stat(".")
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrUnavailable
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		return nil, ErrUnavailable
	}
	current, err := os.Lstat(r.store.path)
	if err != nil || !os.SameFile(info, current) || current.Mode()&os.ModeSymlink != 0 || !outsideGit(r.store.path) {
		return nil, ErrUnavailable
	}
	marker, err := r.readFile(recordMarker, len(recordDomain))
	if err != nil || string(marker) != recordDomain {
		return nil, ErrUnavailable
	}
	dir, err := r.store.root.Open(".")
	if err != nil {
		return nil, ErrUnavailable
	}
	defer dir.Close()
	entries, err := dir.ReadDir(2*maxRecordFiles + 3)
	if err != nil && err != io.EOF {
		return nil, ErrUnavailable
	}
	if len(entries) > 2*maxRecordFiles+2 {
		return nil, ErrUnavailable
	}
	var ids []string
	imports := 0
	for _, entry := range entries {
		name := entry.Name()
		if name == recordMarker || name == ".vault-write.lock" {
			continue
		}
		if strings.HasPrefix(name, importPrefix) {
			imports++
			if imports > maxRecordFiles {
				return nil, ErrUnavailable
			}
			if entry.IsDir() || !nativeRevision(strings.TrimPrefix(name, importPrefix)) {
				return nil, ErrUnavailable
			}
			if _, e := r.readFile(name, 4096); e != nil {
				return nil, e
			}
			continue
		}
		id := strings.TrimSuffix(name, ".record")
		if entry.IsDir() || !strings.HasSuffix(name, ".record") || !nativeRevision(id) {
			return nil, ErrUnavailable
		}
		ids = append(ids, id)
	}
	if len(ids) > maxRecordFiles {
		return nil, ErrUnavailable
	}
	sort.Strings(ids)
	return ids, nil
}
func (r *RecordStore) load(ctx context.Context, ns, id string) (RecordMetadata, []byte, error) {
	if !nativeRevision(id) {
		return RecordMetadata{}, nil, ErrRecord
	}
	b, err := r.readFile(id+".record", maxRecordEnvelope)
	if err != nil {
		return RecordMetadata{}, nil, err
	}
	var e recordEnvelope
	if json.Unmarshal(b, &e) != nil {
		return RecordMetadata{}, nil, ErrUnavailable
	}
	tag, err := r.tag(ctx, e, id)
	if err != nil || len(e.Tag) != sha256.Size || !hmac.Equal(tag, e.Tag) {
		return RecordMetadata{}, nil, ErrUnavailable
	}
	if e.Namespace != ns {
		return RecordMetadata{}, nil, ErrMissing
	}
	plain, err := r.store.cipher.Decrypt(ctx, &kms.Key{Raw: e.Version, Path: recordPath(ns, id)}, e.Ciphertext)
	if err != nil {
		clear(plain)
		return RecordMetadata{}, nil, ErrUnavailable
	}
	if _, _, err = parseRecord(plain); err != nil {
		clear(plain)
		return RecordMetadata{}, nil, ErrUnavailable
	}
	sum := sha256.Sum256(b)
	return RecordMetadata{Reference: RecordReference{ID: id}, Revision: hex.EncodeToString(sum[:])}, plain, nil
}
func (r *RecordStore) scan(ctx context.Context, ns string, key []byte, except string) ([]RecordMetadata, error) {
	ids, err := r.ids()
	if err != nil {
		return nil, err
	}
	result := make([]RecordMetadata, 0, len(ids))
	for _, id := range ids {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		meta, plain, e := r.load(ctx, ns, id)
		if errors.Is(e, ErrMissing) {
			continue
		}
		if e != nil {
			return nil, e
		}
		storedKey, _, e := parseRecord(plain)
		duplicate := e == nil && key != nil && id != except && bytes.Equal(storedKey, key)
		clear(plain)
		if e != nil {
			return nil, ErrUnavailable
		}
		if duplicate {
			return nil, ErrConflict
		}
		result = append(result, meta)
	}
	return result, nil
}
func (r *RecordStore) Inventory(ctx context.Context) ([]RecordMetadata, error) {
	ns, err := recordAdmin(ctx)
	if err != nil {
		return nil, err
	}
	var result []RecordMetadata
	err = r.store.writeLock(ctx, func() error { var e error; result, e = r.scan(ctx, ns, nil, ""); return e })
	if err != nil {
		return nil, err
	}
	return result, nil
}
func (r *RecordStore) Metadata(ctx context.Context, ref RecordReference) (RecordMetadata, error) {
	ns, err := recordAdmin(ctx)
	if err != nil {
		return RecordMetadata{}, err
	}
	var result RecordMetadata
	err = r.store.writeLock(ctx, func() error {
		if _, e := r.ids(); e != nil {
			return e
		}
		meta, plain, e := r.load(ctx, ns, ref.ID)
		clear(plain)
		result = meta
		return e
	})
	return result, err
}

// Lookup accepts a sensitive arbitrary key only from native-human code. It
// consumes/wipes key on every path and returns opaque metadata only.
func (r *RecordStore) Lookup(ctx context.Context, key []byte) (RecordMetadata, error) {
	defer clear(key)
	ns, err := recordAdmin(ctx)
	if err != nil {
		return RecordMetadata{}, err
	}
	if len(key) == 0 || len(key) > maxRecordKey {
		return RecordMetadata{}, ErrRecord
	}
	var result RecordMetadata
	err = r.store.writeLock(ctx, func() error {
		ids, e := r.ids()
		if e != nil {
			return e
		}
		found := false
		for _, id := range ids {
			meta, plain, e := r.load(ctx, ns, id)
			if errors.Is(e, ErrMissing) {
				continue
			}
			if e != nil {
				return e
			}
			stored, _, e := parseRecord(plain)
			match := bytes.Equal(stored, key)
			clear(plain)
			if e != nil {
				return ErrUnavailable
			}
			if match {
				if found {
					return ErrUnavailable
				}
				found = true
				result = meta
			}
		}
		if !found {
			return ErrMissing
		}
		return nil
	})
	if err != nil {
		return RecordMetadata{}, err
	}
	return result, nil
}
func (r *RecordStore) save(ctx context.Context, ns, id string, plain []byte) (RecordMetadata, error) {
	encrypted, err := r.store.cipher.Encrypt(ctx, &kms.Key{Raw: r.store.version, Path: recordPath(ns, id)}, plain)
	if err != nil {
		return RecordMetadata{}, ErrUnavailable
	}
	e := recordEnvelope{Kind: recordDomain, Version: r.store.version, Namespace: ns, Ciphertext: encrypted}
	e.Tag, err = r.tag(ctx, e, id)
	if err != nil {
		return RecordMetadata{}, ErrUnavailable
	}
	encoded, err := json.Marshal(e)
	if err != nil || len(encoded) > maxRecordEnvelope {
		return RecordMetadata{}, ErrUnavailable
	}
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return RecordMetadata{}, ErrUnavailable
	}
	temp := "." + hex.EncodeToString(random) + ".tmp"
	f, err := r.store.root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return RecordMetadata{}, ErrUnavailable
	}
	defer r.store.root.Remove(temp)
	_, err = f.Write(encoded)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return RecordMetadata{}, ErrUnavailable
	}
	if err = ctx.Err(); err != nil {
		return RecordMetadata{}, err
	}
	if err = r.store.root.Rename(temp, id+".record"); err != nil {
		return RecordMetadata{}, ErrUnavailable
	}
	if err = r.sync(); err != nil {
		return RecordMetadata{}, err
	}
	sum := sha256.Sum256(encoded)
	return RecordMetadata{Reference: RecordReference{ID: id}, Revision: hex.EncodeToString(sum[:])}, nil
}
func (r *RecordStore) sync() error {
	dir, err := r.store.root.Open(".")
	if err != nil {
		return ErrUnavailable
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}

// Create and Update consume values exactly once, including on authorization,
// validation, cancellation and revision failure. Future UI wiring must establish
// secure entry/capture suppression before calling these native-human operations.
func (r *RecordStore) Create(ctx context.Context, values RecordValues) (RecordMetadata, error) {
	return r.create(ctx, values, "")
}

// fixedID is available only to the protected native import reservation.
func (r *RecordStore) create(ctx context.Context, values RecordValues, fixedID string) (RecordMetadata, error) {
	defer values.Destroy()
	ns, err := recordAdmin(ctx)
	if err != nil {
		return RecordMetadata{}, err
	}
	plain, err := values.take()
	if err != nil {
		return RecordMetadata{}, err
	}
	defer clear(plain)
	key, _, _ := parseRecord(plain)
	var result RecordMetadata
	err = r.store.writeLock(ctx, func() error {
		entries, e := r.scan(ctx, ns, key, "")
		if e != nil {
			return e
		}
		if len(entries) >= maxRecordFiles {
			return ErrUnavailable
		}
		ids, e := r.ids()
		if e != nil || len(ids) >= maxRecordFiles {
			return ErrUnavailable
		}
		random := make([]byte, 32)
		if _, e = rand.Read(random); e != nil {
			return ErrUnavailable
		}
		id := hex.EncodeToString(random)
		if fixedID != "" {
			if !nativeRevision(fixedID) {
				return ErrUnavailable
			}
			id = fixedID
		}
		if _, e = r.store.root.Lstat(id + ".record"); !os.IsNotExist(e) {
			return ErrConflict
		}
		result, e = r.save(ctx, ns, id, plain)
		return e
	})
	return result, err
}
func (r *RecordStore) Update(ctx context.Context, ref RecordReference, revision string, values RecordValues) (RecordMetadata, error) {
	defer values.Destroy()
	ns, err := recordAdmin(ctx)
	if err != nil {
		return RecordMetadata{}, err
	}
	plain, err := values.take()
	if err != nil {
		return RecordMetadata{}, err
	}
	defer clear(plain)
	key, _, _ := parseRecord(plain)
	var result RecordMetadata
	err = r.store.writeLock(ctx, func() error {
		if _, e := r.scan(ctx, ns, key, ref.ID); e != nil {
			return e
		}
		meta, old, e := r.load(ctx, ns, ref.ID)
		clear(old)
		if e != nil {
			return e
		}
		if len(revision) != 64 || subtle.ConstantTimeCompare([]byte(meta.Revision), []byte(revision)) != 1 {
			return ErrConflict
		}
		result, e = r.save(ctx, ns, ref.ID, plain)
		return e
	})
	return result, err
}
func (r *RecordStore) Delete(ctx context.Context, ref RecordReference, revision string) error {
	ns, err := recordAdmin(ctx)
	if err != nil {
		return err
	}
	return r.store.writeLock(ctx, func() error {
		if _, e := r.ids(); e != nil {
			return e
		}
		meta, plain, e := r.load(ctx, ns, ref.ID)
		clear(plain)
		if e != nil {
			return e
		}
		if len(revision) != 64 || subtle.ConstantTimeCompare([]byte(meta.Revision), []byte(revision)) != 1 {
			return ErrConflict
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		if e = r.store.root.Remove(ref.ID + ".record"); e != nil {
			return ErrUnavailable
		}
		return r.sync()
	})
}
