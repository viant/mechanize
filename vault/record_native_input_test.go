package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/scy/kms"
)

func recordEntryTarget() Target {
	return Target{Origin: NativeRecordEntryOrigin, Account: "account-00112233-4455-6677-8899-aabbccddeeff"}
}

type recordServiceProtection struct {
	mode     string
	calls    int
	after    func()
	retained func() error
}

func (p *recordServiceProtection) WithEntry(_ context.Context, _ Target, action func() error) error {
	p.calls++
	switch p.mode {
	case "deny":
		return errors.New("synthetic-private-protection-error")
	case "skip":
		return nil
	case "retain":
		p.retained = action
		return nil
	case "concurrent-double":
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); _ = action() }()
		}
		wg.Wait()
		return nil
	}
	err := action()
	if p.after != nil {
		p.after()
	}
	switch p.mode {
	case "double":
		_ = action()
		return nil
	case "swallow":
		return nil
	case "lost-ack":
		return errors.New("synthetic-private-protection-error")
	}
	return err
}
func recordService(t *testing.T, protection NativeEntryProtection) (*NativeRecordInputService, *RecordStore) {
	t.Helper()
	store := fixtureRecordStore(t)
	service, err := NewNativeRecordInputService(store, protection)
	if err != nil {
		t.Fatal(err)
	}
	return service, store
}
func TestNativeRecordAdmissionRefusesBeforeAnySecretRead(t *testing.T) {
	for _, mode := range []string{"agent", "no-identity", "cancelled", "foreign-origin", "path-origin", "plain-account", "uppercase-uuid", "unready", "unprotected", "nil-service", "bad-ref", "bad-revision", "stale-revision", "missing-ref", "foreign-ref"} {
		t.Run(mode, func(t *testing.T) {
			guard := &recordServiceProtection{}
			service, store := recordService(t, guard)
			ctx := fixtureContext("native-record", true)
			target := recordEntryTarget()
			meta, err := store.Create(ctx, goldenRecordValues(t))
			if err != nil {
				t.Fatal(err)
			}
			ref, revision := meta.Reference, meta.Revision
			update := false
			switch mode {
			case "agent":
				ctx = fixtureContext("native-record", false)
			case "no-identity":
				ctx = context.Background()
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "foreign-origin":
				target.Origin = "https://example.test"
			case "path-origin":
				target.Origin += "/path"
			case "plain-account":
				target.Account = "record-key"
			case "uppercase-uuid":
				target.Account = strings.ToUpper(target.Account)
			case "unready":
				store.store.cipher = &Cipher{Keys: unavailableNativeKeys{}}
			case "unprotected":
				guard.mode = "deny"
			case "nil-service":
				service = nil
			case "bad-ref":
				update = true
				ref.ID = "invalid"
			case "bad-revision":
				update = true
				revision = "invalid"
			case "stale-revision":
				update = true
				revision = strings.Repeat("0", 64)
			case "missing-ref":
				update = true
				ref.ID = strings.Repeat("1", 64)
			case "foreign-ref":
				update = true
				ctx = fixtureContext("different-owner", true)
			}
			reader := &countingNativeReader{reader: bytes.NewReader(goldenRecordFrame(t))}
			if update {
				_, err = service.Update(ctx, target, ref, revision, reader)
			} else {
				_, err = service.Create(ctx, target, reader)
			}
			if err == nil || strings.Contains(err.Error(), "synthetic") {
				t.Fatal("unsafe admission/error", err)
			}
			if reader.reads != 0 {
				t.Fatal("read before complete native admission")
			}
		})
	}
}
func TestNativeRecordCRUDIsOpaqueAndRevisionBound(t *testing.T) {
	guard := &recordServiceProtection{}
	service, store := recordService(t, guard)
	ctx := fixtureContext("native-record", true)
	target := recordEntryTarget()
	if service.ExposureGate() != nil {
		t.Fatal("fixture adapter misrepresented as shared gate")
	}
	if err := service.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	meta, err := service.Create(ctx, target, bytes.NewReader(goldenRecordFrame(t)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(meta)
	if err != nil || strings.Contains(string(b), "arbitrary") || strings.Contains(string(b), "login") || strings.Contains(string(b), target.Origin) || strings.Contains(string(b), target.Account) {
		t.Fatal("public metadata contains secret or binding")
	}
	updated, err := service.Update(ctx, target, meta.Reference, meta.Revision, bytes.NewReader(goldenRecordFrame(t)))
	if err != nil || updated.Reference != meta.Reference || updated.Revision == meta.Revision {
		t.Fatal("update", err)
	}
	reader := &countingNativeReader{reader: bytes.NewReader(goldenRecordFrame(t))}
	if _, err = service.Update(ctx, target, meta.Reference, meta.Revision, reader); !errors.Is(err, ErrConflict) || reader.reads != 0 {
		t.Fatal("stale update consumed incoming secrets", err)
	}
	if err = service.Delete(ctx, target, meta.Reference, meta.Revision); !errors.Is(err, ErrConflict) {
		t.Fatal("stale delete", err)
	}
	if err = service.Delete(ctx, target, updated.Reference, updated.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Metadata(ctx, meta.Reference); !errors.Is(err, ErrMissing) {
		t.Fatal("delete failed", err)
	}
	if guard.calls != 5 {
		t.Fatal("missing protection admission", guard.calls)
	}
	// The permitted hex binding is independent of the arbitrary key and fields.
	target.Account = strings.Repeat("a", 64)
	if _, err = service.Create(ctx, target, bytes.NewReader(goldenRecordFrame(t))); err != nil {
		t.Fatal("hex entry binding", err)
	}
}
func TestNativeRecordProtectionCallbackMustRunExactlyOnce(t *testing.T) {
	for _, mode := range []string{"skip", "retain", "double", "concurrent-double", "swallow"} {
		t.Run(mode, func(t *testing.T) {
			guard := &recordServiceProtection{mode: mode}
			service, store := recordService(t, guard)
			ctx := fixtureContext("native-record", true)
			frame := goldenRecordFrame(t)
			if mode == "swallow" {
				frame = frame[:15]
			}
			reader := &countingNativeReader{reader: bytes.NewReader(frame)}
			meta, err := service.Create(ctx, recordEntryTarget(), reader)
			expected := ErrUnavailable
			if mode == "double" || mode == "concurrent-double" {
				expected = ErrNativeOutcomeUnknown
			}
			if mode == "swallow" {
				expected = ErrNativeInput
			}
			if !errors.Is(err, expected) || meta != (RecordMetadata{}) {
				t.Fatal("callback contract escaped", err)
			}
			if mode == "skip" || mode == "retain" {
				if reader.reads != 0 {
					t.Fatal("skipped callback read data")
				}
				if mode == "retain" {
					if err = guard.retained(); !errors.Is(err, ErrUnavailable) || reader.reads != 0 {
						t.Fatal("late callback read data", err)
					}
				}
			}
			rows, e := store.Inventory(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "double" || mode == "concurrent-double" {
				if len(rows) != 1 || reader.reads != 3 {
					t.Fatal("duplicate callback read/replayed administration")
				}
			} else if len(rows) != 0 {
				t.Fatal("failed admission mutated store")
			}
		})
	}
}
func TestNativeRecordLostAcknowledgementAndPostWriteCancellationAreUnknown(t *testing.T) {
	for _, mode := range []string{"lost-ack", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			guard := &recordServiceProtection{}
			service, store := recordService(t, guard)
			human := fixtureContext("native-record", true)
			ctx, cancel := context.WithCancel(human)
			defer cancel()
			if mode == "lost-ack" {
				guard.mode = "lost-ack"
			} else {
				guard.after = cancel
			}
			meta, err := service.Create(ctx, recordEntryTarget(), bytes.NewReader(goldenRecordFrame(t)))
			if !errors.Is(err, ErrNativeOutcomeUnknown) || meta != (RecordMetadata{}) {
				t.Fatal("lost acknowledgement treated as definitive", err)
			}
			rows, err := store.Inventory(human)
			if err != nil || len(rows) != 1 {
				t.Fatal("committed record not independently inspectable", err)
			}
		})
	}
	guard := &recordServiceProtection{}
	service, store := recordService(t, guard)
	ctx := fixtureContext("native-record", true)
	target := recordEntryTarget()
	meta, err := service.Create(ctx, target, bytes.NewReader(goldenRecordFrame(t)))
	if err != nil {
		t.Fatal(err)
	}
	guard.mode = "lost-ack"
	if err = service.Delete(ctx, target, meta.Reference, meta.Revision); !errors.Is(err, ErrNativeOutcomeUnknown) {
		t.Fatal("delete lost acknowledgement", err)
	}
	if _, err = store.Metadata(ctx, meta.Reference); !errors.Is(err, ErrMissing) {
		t.Fatal("delete did not commit", err)
	}
}

type nativeRecordReaderHook struct {
	reader io.Reader
	before func()
	once   sync.Once
}

func (r *nativeRecordReaderHook) Read(p []byte) (int, error) {
	r.once.Do(r.before)
	return r.reader.Read(p)
}
func TestNativeRecordUpdateRepeatsAtomicCASAfterFrameRead(t *testing.T) {
	service, store := recordService(t, &recordServiceProtection{})
	ctx := fixtureContext("native-record", true)
	target := recordEntryTarget()
	meta, err := service.Create(ctx, target, bytes.NewReader(goldenRecordFrame(t)))
	if err != nil {
		t.Fatal(err)
	}
	var concurrent RecordMetadata
	reader := &nativeRecordReaderHook{reader: bytes.NewReader(goldenRecordFrame(t)), before: func() {
		concurrent, err = store.Update(ctx, meta.Reference, meta.Revision, recordValues(t, "concurrent-key"))
		if err != nil {
			t.Fatal(err)
		}
	}}
	if _, err = service.Update(ctx, target, meta.Reference, meta.Revision, reader); !errors.Is(err, ErrNativeOutcomeUnknown) {
		t.Fatal("final CAS lost update", err)
	}
	actual, err := store.Metadata(ctx, meta.Reference)
	if err != nil || actual != concurrent {
		t.Fatal("concurrent value overwritten", err)
	}
}

type recordGateCipher struct {
	*Cipher
	gate *ExposureGate
	seen bool
}

func (c *recordGateCipher) Ready(ctx context.Context, version string) error {
	if release, err := c.gate.AcquireExposureContext(ctx); err == nil {
		release()
		return errors.New("unprotected readiness")
	}
	return c.Cipher.Ready(ctx, version)
}
func (c *recordGateCipher) Encrypt(ctx context.Context, key *kms.Key, plain []byte) ([]byte, error) {
	if release, err := c.gate.AcquireExposureContext(ctx); err == nil {
		release()
		return nil, errors.New("unprotected encryption")
	}
	c.seen = true
	return c.Cipher.Encrypt(ctx, key, plain)
}
func TestNativeRecordActualSharedGateBlocksExposureThroughSecretLifetime(t *testing.T) {
	gate := &ExposureGate{}
	service, store := recordService(t, gate)
	ctx := fixtureContext("native-record", true)
	target := recordEntryTarget()
	if service.ExposureGate() != gate {
		t.Fatal("gate identity lost")
	}
	reader := &countingNativeReader{reader: bytes.NewReader(goldenRecordFrame(t))}
	if _, err := service.Create(ctx, target, reader); !errors.Is(err, ErrUnavailable) || reader.reads != 0 {
		t.Fatal("unprotected gate admitted", err)
	}
	lease, err := gate.Begin(ctx, target, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	cipher := &recordGateCipher{Cipher: store.store.cipher.(*Cipher), gate: gate}
	store.store.cipher = cipher
	readerHook := &nativeRecordReaderHook{reader: bytes.NewReader(goldenRecordFrame(t)), before: func() {
		if release, err := gate.AcquireExposureContext(ctx); !errors.Is(err, ErrEntryProtected) {
			if release != nil {
				release()
			}
			t.Fatal("exposure during frame read")
		}
		if err := lease.Close(ctx); !errors.Is(err, ErrBusy) {
			t.Fatal("lease released during frame read", err)
		}
	}}
	// Close above retires the lease, but the already admitted operation retains
	// its in-flight protection until all record bytes have been destroyed.
	if _, err = service.Create(ctx, target, readerHook); err != nil {
		t.Fatal(err)
	}
	if !cipher.seen {
		t.Fatal("encrypted storage path not exercised")
	}
	if err = lease.Close(ctx); err != nil {
		t.Fatal(err)
	}
	release, err := gate.AcquireExposureContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	release()
}
func TestNativeRecordPlaintextWipedBeforeProtectionReturns(t *testing.T) {
	guard := &recordServiceProtection{}
	service, store := recordService(t, guard)
	ctx := fixtureContext("native-record", true)
	cipher := &recordBufferSpy{Cipher: store.store.cipher.(*Cipher)}
	store.store.cipher = cipher
	reader := &recordFrameReaderSpy{reader: bytes.NewReader(goldenRecordFrame(t))}
	guard.after = func() { assertFrameBuffersWiped(t, reader.buffers); assertFrameBuffersWiped(t, cipher.plaintext) }
	if _, err := service.Create(ctx, recordEntryTarget(), reader); err != nil {
		t.Fatal(err)
	}
}
func TestNativeRecordDeleteAndReadinessAdmission(t *testing.T) {
	service, store := recordService(t, &recordServiceProtection{})
	human := fixtureContext("native-record", true)
	agent := fixtureContext("native-record", false)
	meta, err := store.Create(human, goldenRecordValues(t))
	if err != nil {
		t.Fatal(err)
	}
	if err = service.Ready(agent); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal(err)
	}
	if err = service.Delete(agent, recordEntryTarget(), meta.Reference, meta.Revision); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal(err)
	}
	if err = service.Delete(human, recordEntryTarget(), RecordReference{ID: "bad"}, meta.Revision); !errors.Is(err, ErrRecord) {
		t.Fatal(err)
	}
	if err = service.Delete(human, recordEntryTarget(), meta.Reference, "bad"); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	store.store.cipher = &Cipher{Keys: unavailableNativeKeys{}}
	if err = service.Delete(human, recordEntryTarget(), meta.Reference, meta.Revision); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err = NewNativeRecordInputService(nil, &recordServiceProtection{}); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err = NewNativeRecordInputService(store, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err = NewNativeRecordInputService(store, (*ExposureGate)(nil)); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestNativeRecordCancellationAfterFrameDecodeWipesWithoutAdministration(t *testing.T) {
	guard := &recordServiceProtection{}
	service, store := recordService(t, guard)
	human := fixtureContext("native-record", true)
	ctx, cancel := context.WithCancel(human)
	defer cancel()
	reader := &recordFrameReaderSpy{reader: &cancelOnRecordEOF{reader: bytes.NewReader(goldenRecordFrame(t)), cancel: cancel}}
	guard.after = func() { assertFrameBuffersWiped(t, reader.buffers) }
	if meta, err := service.Create(ctx, recordEntryTarget(), reader); !errors.Is(err, ErrUnavailable) || meta != (RecordMetadata{}) {
		t.Fatal("pre-administration cancellation misclassified", err)
	}
	rows, err := store.Inventory(human)
	if err != nil || len(rows) != 0 {
		t.Fatal("cancelled input reached administration", err)
	}
}

type cancelOnRecordEOF struct {
	reader *bytes.Reader
	cancel context.CancelFunc
}

func (r *cancelOnRecordEOF) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if err == io.EOF {
		r.cancel()
	}
	return n, err
}

func TestNativeRecordSharedGateRequiresExactLifecycleBinding(t *testing.T) {
	gate := &ExposureGate{}
	service, _ := recordService(t, gate)
	ctx := fixtureContext("native-record", true)
	target := recordEntryTarget()
	lease, err := gate.Begin(ctx, target, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close(ctx)
	other := target
	other.Account = strings.Repeat("b", 64)
	reader := &countingNativeReader{reader: bytes.NewReader(goldenRecordFrame(t))}
	if _, err = service.Create(ctx, other, reader); !errors.Is(err, ErrUnavailable) || reader.reads != 0 {
		t.Fatal("different lifecycle admitted", err)
	}
	foreign := fixtureContext("other-owner", true)
	if _, err = service.Create(foreign, target, reader); !errors.Is(err, ErrUnavailable) || reader.reads != 0 {
		t.Fatal("foreign lifecycle admitted", err)
	}
}
