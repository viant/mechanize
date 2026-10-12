package vault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/viant/mechanize/security/keychain"
)

func TestMissingMasterKeyCreationCustodyRefusesEveryNonLockFile(t *testing.T) {
	ctx := fixtureContext("key-custody", true)
	for _, name := range []string{"opaque.enc", "unknown-backup", "nested", ""} {
		t.Run(name, func(t *testing.T) {
			store := fixtureStore(t)
			if name == "nested" {
				if err := store.root.Mkdir(name, 0700); err != nil {
					t.Fatal(err)
				}
			} else if name != "" {
				f, err := store.root.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				f.Close()
			}
			err := store.writeLock(ctx, func() error { return store.requireEmptyForKeyCreation(ctx) })
			if name == "" && err != nil {
				t.Fatal("private empty custody refused")
			}
			if name != "" && !errors.Is(err, ErrUnavailable) {
				t.Fatal("existing encrypted/unknown material allowed a replacement key")
			}
		})
	}
}

func TestMissingMasterKeyGuardIncludesGenericRecordsUnderBothLocks(t *testing.T) {
	for _, content := range []string{"empty", "record", "unknown"} {
		t.Run(content, func(t *testing.T) {
			credentials := fixtureStore(t)
			records := fixtureRecordStore(t)
			records.store.cipher = credentials.cipher // Exact enrolled shared cipher.
			setup, err := NewNativeKeySetupWithRecords(credentials, &keychain.MasterKeyProvisioner{}, records)
			if err != nil {
				t.Fatal(err)
			}
			ctx := fixtureContext("multi-store-key-custody", true)
			if content == "record" {
				if _, err = records.Create(ctx, recordValues(t, "synthetic-record")); err != nil {
					t.Fatal(err)
				}
			}
			if content == "unknown" {
				f, e := records.store.root.OpenFile("unknown", os.O_CREATE|os.O_WRONLY, 0600)
				if e != nil {
					t.Fatal(e)
				}
				f.Close()
			}
			err = setup.withCiphertextLocks(ctx, func() error {
				if e := records.store.writeLock(ctx, func() error { t.Fatal("record lock not held"); return nil }); !errors.Is(e, ErrBusy) {
					t.Fatal("record custody lock unavailable", e)
				}
				return setup.requireEmptyForKeyCreation(ctx)
			})
			if content == "empty" && err != nil || content != "empty" && !errors.Is(err, ErrUnavailable) {
				t.Fatal("missing-master guard did not preserve both ciphertext stores", err)
			}
		})
	}
}

func TestNativeRecordKeySetupRejectsDifferentCipherVersionOrOverlappingRoot(t *testing.T) {
	credentials := fixtureStore(t)
	records := fixtureRecordStore(t)
	provisioner := &keychain.MasterKeyProvisioner{} // Constructor checks only; no Keychain calls.
	if _, err := NewNativeKeySetupWithRecords(credentials, provisioner, records); !errors.Is(err, ErrUnavailable) {
		t.Fatal("different cipher accepted")
	}
	records.store.cipher = credentials.cipher
	records.store.version = "different-version"
	if _, err := NewNativeKeySetupWithRecords(credentials, provisioner, records); !errors.Is(err, ErrUnavailable) {
		t.Fatal("different key version accepted")
	}
	records.store.version = credentials.version
	oldPath := records.store.path
	records.store.path = credentials.path + "/records"
	if _, err := NewNativeKeySetupWithRecords(credentials, provisioner, records); !errors.Is(err, ErrUnavailable) {
		t.Fatal("overlapping roots accepted")
	}
	records.store.path = oldPath
	setup, err := NewNativeKeySetupWithRecords(credentials, provisioner, records)
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewNativeRecordInputService(records, &ExposureGate{})
	if err != nil || !setup.MatchesRecordInput(input) {
		t.Fatal("matching record custody not established", err)
	}
}

type unavailableNativeKeys struct{}

func (unavailableNativeKeys) Resolve(context.Context, string) ([]byte, error) {
	return nil, errors.New("private-key-unavailable-canary")
}
func TestNativeInputMissingKeyRefusesBeforeCredentialRead(t *testing.T) {
	store := fixtureStore(t)
	store.cipher = &Cipher{Keys: unavailableNativeKeys{}}
	service, err := NewNativeInputService(store, &fixtureProtection{})
	if err != nil {
		t.Fatal(err)
	}
	reader := &countingNativeReader{reader: bytes.NewReader(fixtureNativeFrame([]byte("synthetic-user"), []byte("synthetic-password")))}
	if _, err = service.Create(fixtureContext("key-custody", true), fixtureBinding().Target, reader); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing key admitted input")
	}
	if reader.reads != 0 {
		t.Fatal("credential bytes requested before master-key readiness")
	}
}
