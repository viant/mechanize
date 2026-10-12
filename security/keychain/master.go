package keychain

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"

	"github.com/viant/mechanize/auth"
)

var ErrMasterKeyUnavailable = errors.New("native master-key provisioning unavailable")

type MasterKeyOptions struct {
	Alias             string
	Item              Item
	BrokerRequirement string
}
type masterKeyStore interface {
	inspect(context.Context) ([]byte, error)
	read(context.Context, []byte) ([]byte, error)
	add(context.Context, []byte) ([]byte, error)
}
type masterKeyAccessRefresher interface {
	refreshAccess(context.Context, []byte) ([]byte, error)
}

// MasterKeyProvisioner creates a key in the signed broker's own Keychain
// partition. It returns only the enrolled resource reference. No key bytes are
// accepted from callers, exposed as results, persisted to files or sent to UI.
type MasterKeyProvisioner struct {
	reference string
	store     masterKeyStore
	entropy   io.Reader
}

func NewMasterKeyProvisioner(options MasterKeyOptions) (*MasterKeyProvisioner, error) {
	ref, err := Reference(options.Alias)
	if err != nil || strings.TrimSpace(options.Item.Service) == "" || strings.TrimSpace(options.Item.Account) == "" || strings.TrimSpace(options.BrokerRequirement) == "" || strings.ContainsRune(options.Item.Service+options.Item.Account+options.BrokerRequirement, 0) {
		return nil, ErrMasterKeyUnavailable
	}
	store, err := newMasterKeyStore(options)
	if err != nil {
		return nil, ErrMasterKeyUnavailable
	}
	p := &MasterKeyProvisioner{reference: ref, store: store, entropy: rand.Reader}
	return masterReaders.enroll(options, p)
}
func (p *MasterKeyProvisioner) Ready(ctx context.Context) error {
	if !auth.NativeHuman(ctx) {
		return auth.ErrUnauthorized
	}
	if p == nil || p.store == nil || ctx.Err() != nil {
		return ErrMasterKeyUnavailable
	}
	material, err := p.readVerified(ctx)
	defer clear(material)
	if err != nil {
		return ErrMasterKeyUnavailable
	}
	key, err := decodeMasterKey(material)
	defer clear(key)
	if err != nil || ctx.Err() != nil {
		return ErrMasterKeyUnavailable
	}
	return nil
}

// An identity is an opaque persistent item reference, not service/account
// metadata. Inspection must reject duplicate matches and unverified custody.
func (p *MasterKeyProvisioner) readVerified(ctx context.Context) ([]byte, error) {
	identity, err := p.store.inspect(ctx)
	if err != nil || !validMasterIdentity(identity) {
		return nil, ErrMasterKeyUnavailable
	}
	return p.readIdentity(ctx, identity)
}
func validMasterIdentity(identity []byte) bool { return len(identity) > 0 && len(identity) <= 16384 }
func (p *MasterKeyProvisioner) readIdentity(ctx context.Context, identity []byte) ([]byte, error) {
	material, err := p.store.read(ctx, identity)
	current, inspectErr := p.store.inspect(ctx)
	if err != nil || inspectErr != nil || !validMasterIdentity(current) || !bytes.Equal(identity, current) || ctx.Err() != nil {
		clear(material)
		return nil, ErrMasterKeyUnavailable
	}
	return material, nil
}
func decodeMasterKey(material []byte) ([]byte, error) {
	if len(material) == 0 || len(material) > 256 {
		return nil, ErrMasterKeyUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(material))
	decoder.DisallowUnknownFields()
	var value struct {
		Key []byte `json:"key"`
	}
	if decoder.Decode(&value) != nil || len(value.Key) != 32 || decoder.Decode(new(any)) != io.EOF {
		clear(value.Key)
		return nil, ErrMasterKeyUnavailable
	}
	return value.Key, nil
}

// Ensure is exclusive to native-human setup. canCreate is a trusted custody
// check that refuses key replacement when encrypted data already exists. It
// receives no keys. Duplicate items, failed reads and invalid existing keys are
// preserved. Explicit native setup may refresh an existing ACL's legacy image
// metadata only when its signing identity and permissions are unchanged. It
// never replaces a key or retries an uncertain metadata write.
func (p *MasterKeyProvisioner) Ensure(ctx context.Context, canCreate func(context.Context) error) (string, error) {
	if !auth.NativeHuman(ctx) {
		return "", auth.ErrUnauthorized
	}
	if p == nil || p.store == nil || p.entropy == nil || canCreate == nil || ctx.Err() != nil {
		return "", ErrMasterKeyUnavailable
	}
	identity, err := p.store.inspect(ctx)
	if err != nil {
		return "", ErrMasterKeyUnavailable
	}
	if len(identity) != 0 {
		if !validMasterIdentity(identity) {
			return "", ErrMasterKeyUnavailable
		}
		material, readErr := p.readIdentity(ctx, identity)
		if readErr != nil {
			clear(material)
			refresh, ok := p.store.(masterKeyAccessRefresher)
			if !ok || ctx.Err() != nil {
				return "", ErrMasterKeyUnavailable
			}
			confirmed, refreshErr := refresh.refreshAccess(ctx, identity)
			if refreshErr != nil || !bytes.Equal(identity, confirmed) || ctx.Err() != nil {
				return "", ErrMasterKeyUnavailable
			}
			material, readErr = p.readIdentity(ctx, identity)
		}
		defer clear(material)
		key, keyErr := decodeMasterKey(material)
		defer clear(key)
		if readErr != nil || keyErr != nil {
			return "", ErrMasterKeyUnavailable
		}
		return p.reference, nil
	}
	if canCreate(ctx) != nil || ctx.Err() != nil {
		return "", ErrMasterKeyUnavailable
	}
	key := make([]byte, 32)
	defer clear(key)
	if _, err = io.ReadFull(p.entropy, key); err != nil {
		return "", ErrMasterKeyUnavailable
	}
	material, err := json.Marshal(struct {
		Key []byte `json:"key"`
	}{Key: key})
	defer clear(material)
	if err != nil || ctx.Err() != nil {
		return "", ErrMasterKeyUnavailable
	}
	created, err := p.store.add(ctx, material)
	if err != nil || !validMasterIdentity(created) {
		return "", ErrMasterKeyUnavailable
	}
	// Pin the exact item returned by creation, recheck custody/uniqueness, and
	// compare decoded keys in constant time. Never adopt a same-shaped substitute.
	readback, err := p.readIdentity(ctx, created)
	defer clear(readback)
	actual, decodeErr := decodeMasterKey(readback)
	defer clear(actual)
	if err != nil || decodeErr != nil || subtle.ConstantTimeCompare(key, actual) != 1 || ctx.Err() != nil {
		return "", ErrMasterKeyUnavailable
	}
	return p.reference, nil
}

// The provider may be registered before native Vault construction. Dispatch is
// looked up on each read, so the enrolled master item cannot use generic lookup.
type masterReaderEnrollment struct {
	options MasterKeyOptions
	reader  *MasterKeyProvisioner
}
type masterReaderRegistry struct {
	sync.RWMutex
	items map[Item]masterReaderEnrollment
}

var masterReaders = masterReaderRegistry{items: make(map[Item]masterReaderEnrollment)}

func (r *masterReaderRegistry) enroll(options MasterKeyOptions, p *MasterKeyProvisioner) (*MasterKeyProvisioner, error) {
	r.Lock()
	defer r.Unlock()
	if prior, ok := r.items[options.Item]; ok {
		if prior.options != options {
			return nil, ErrMasterKeyUnavailable
		}
		return prior.reader, nil
	}
	for _, prior := range r.items {
		if prior.options.Alias == options.Alias {
			return nil, ErrMasterKeyUnavailable
		}
	}
	r.items[options.Item] = masterReaderEnrollment{options: options, reader: p}
	return p, nil
}
func (r *masterReaderRegistry) read(ctx context.Context, item Item) ([]byte, bool, error) {
	r.RLock()
	entry, ok := r.items[item]
	r.RUnlock()
	if !ok {
		return nil, false, nil
	}
	material, err := readMasterEnrollment(ctx, entry)
	return material, true, err
}
func readMasterEnrollment(ctx context.Context, entry masterReaderEnrollment) ([]byte, error) {
	material, err := entry.reader.readVerified(ctx)
	if err != nil {
		return nil, ErrMasterKeyUnavailable
	}
	key, decodeErr := decodeMasterKey(material)
	clear(key)
	if decodeErr != nil {
		clear(material)
		return nil, ErrMasterKeyUnavailable
	}
	return material, nil
}
func (r *masterReaderRegistry) lookup(ctx context.Context, item Item, fallback func(context.Context, Item) ([]byte, error)) ([]byte, error) {
	// Enrollment cannot complete while an older generic lookup is in flight.
	r.RLock()
	defer r.RUnlock()
	if entry, ok := r.items[item]; ok {
		return readMasterEnrollment(ctx, entry)
	}
	return fallback(ctx, item)
}
