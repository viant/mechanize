package vault

import (
	"context"
	"io"
	"path/filepath"
	"reflect"

	"github.com/viant/mechanize/auth"
)

// NativeKeyProvisioner keeps custody behind a native-only administration seam.
// Cipher key resolution stays internal; this interface never returns key bytes.
type NativeKeyProvisioner interface {
	Ready(context.Context) error
	Ensure(context.Context, func(context.Context) error) (string, error)
}

func nilNativeKeyProvisioner(p NativeKeyProvisioner) bool {
	if p == nil {
		return true
	}
	v := reflect.ValueOf(p)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

type NativeKeySetup struct {
	store       *Store
	provisioner NativeKeyProvisioner
	records     *RecordStore
}

func (s *NativeKeySetup) MatchesInput(input *NativeInputService) bool {
	return s != nil && input != nil && s.store == input.store
}
func (s *NativeKeySetup) MatchesRecordInput(input *NativeRecordInputService) bool {
	return s != nil && input != nil && s.records != nil && s.records == input.store && sharedRecordCustody(s.store, s.records)
}
func (s *NativeKeySetup) Ready(ctx context.Context) error {
	if !auth.NativeHuman(ctx) {
		return auth.ErrUnauthorized
	}
	if s == nil || s.store == nil || nilNativeKeyProvisioner(s.provisioner) || s.provisioner.Ready(ctx) != nil {
		return ErrUnavailable
	}
	readiness, ok := s.store.cipher.(interface {
		Ready(context.Context, string) error
	})
	if !ok || readiness.Ready(ctx, s.store.version) != nil {
		return ErrUnavailable
	}
	return nil
}

func NewNativeKeySetup(store *Store, provisioner NativeKeyProvisioner) (*NativeKeySetup, error) {
	if store == nil || nilNativeKeyProvisioner(provisioner) {
		return nil, ErrUnavailable
	}
	return &NativeKeySetup{store: store, provisioner: provisioner}, nil
}

// NewNativeKeySetupWithRecords enrolls both ciphertext roots in missing-key
// protection. A generic record store may not replace the credential store or
// select another cipher/version. The host keeps both roots alive until shutdown.
func NewNativeKeySetupWithRecords(store *Store, provisioner NativeKeyProvisioner, records *RecordStore) (*NativeKeySetup, error) {
	setup, err := NewNativeKeySetup(store, provisioner)
	if err != nil || !sharedRecordCustody(store, records) {
		return nil, ErrUnavailable
	}
	setup.records = records
	return setup, nil
}

func sharedRecordCustody(store *Store, records *RecordStore) bool {
	if store == nil || records == nil || records.store == nil || store == records.store || store.version != records.store.version {
		return false
	}
	credentialCipher, ok := store.cipher.(*Cipher)
	recordCipher, recordOK := records.store.cipher.(*Cipher)
	if !ok || !recordOK || credentialCipher == nil || credentialCipher != recordCipher {
		return false
	}
	for _, pair := range [][2]string{{store.path, records.store.path}, {records.store.path, store.path}} {
		relative, err := filepath.Rel(pair[0], pair[1])
		if err != nil || filepath.IsLocal(relative) {
			return false
		}
	}
	return true
}

// Ensure holds the same private filesystem lock as credential CRUD throughout
// native key provisioning. Existing encrypted/unknown files refuse
// missing-key generation. No ciphertext or key bytes leave this method.
func (s *NativeKeySetup) Ensure(ctx context.Context) error {
	if !auth.NativeHuman(ctx) {
		return auth.ErrUnauthorized
	}
	if s == nil || s.store == nil || nilNativeKeyProvisioner(s.provisioner) {
		return ErrUnavailable
	}
	return s.withCiphertextLocks(ctx, func() error {
		_, err := s.provisioner.Ensure(ctx, s.requireEmptyForKeyCreation)
		if err != nil {
			return ErrUnavailable
		}
		return s.Ready(ctx)
	})
}

func (s *NativeKeySetup) withCiphertextLocks(ctx context.Context, action func() error) error {
	return s.store.writeLock(ctx, func() error {
		if s.records == nil {
			return action()
		}
		if !sharedRecordCustody(s.store, s.records) {
			return ErrUnavailable
		}
		// Fixed credential-then-record ordering. CRUD locks only its own root.
		return s.records.store.writeLock(ctx, action)
	})
}

func (s *NativeKeySetup) requireEmptyForKeyCreation(ctx context.Context) error {
	if err := s.store.requireEmptyForKeyCreation(ctx); err != nil {
		return err
	}
	if s.records == nil {
		return nil
	}
	ids, err := s.records.ids()
	imports, importErr := s.records.importCount()
	if err != nil || len(ids) != 0 || importErr != nil || imports != 0 || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) requireEmptyForKeyCreation(ctx context.Context) error {
	if !auth.NativeHuman(ctx) {
		return auth.ErrUnauthorized
	}
	if ctx.Err() != nil || !outsideGit(s.path) {
		return ErrUnavailable
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return ErrUnavailable
	}
	defer dir.Close()
	entries, err := dir.ReadDir(2)
	if err != nil && err != io.EOF {
		return ErrUnavailable
	}
	for _, entry := range entries {
		if entry.Name() != ".vault-write.lock" {
			return ErrUnavailable
		}
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}
