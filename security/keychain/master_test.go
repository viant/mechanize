package keychain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/viant/mechanize/auth"
)

type masterStoreFixture struct {
	material     []byte
	identity     []byte
	readIdentity []byte
	substitute   bool
	submitted    []byte
	creates      int
	existsError  bool
	readError    bool
	duplicate    bool
}

func (s *masterStoreFixture) inspect(context.Context) ([]byte, error) {
	if s.existsError {
		return nil, errors.New("private-existence-canary")
	}
	if s.material == nil {
		return nil, nil
	}
	if s.identity != nil {
		return append([]byte(nil), s.identity...), nil
	}
	return []byte("synthetic-item-identity"), nil
}
func (s *masterStoreFixture) read(_ context.Context, identity []byte) ([]byte, error) {
	s.readIdentity = append([]byte(nil), identity...)
	if s.readError {
		return nil, errors.New("private-read-canary")
	}
	return append([]byte(nil), s.material...), nil
}
func (s *masterStoreFixture) add(_ context.Context, b []byte) ([]byte, error) {
	s.creates++
	s.submitted = b
	if s.duplicate {
		return nil, errors.New("private-duplicate-canary")
	}
	s.material = append([]byte(nil), b...)
	if s.substitute {
		s.material = []byte(`{"key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`)
	}
	return []byte("synthetic-item-identity"), nil
}
func masterFixtureContext(t *testing.T, human bool) context.Context {
	t.Helper()
	p, _ := auth.NewPrincipal("fixture", "", "native-key-owner", []string{"consent:admin"})
	ctx := auth.WithPrincipal(context.Background(), p)
	if human {
		ctx, _ = auth.WithNativeHuman(ctx)
	}
	return ctx
}
func TestNativeMasterProvisioningReturnsReferenceOnlyAndWipesTemporaryPayload(t *testing.T) {
	store := &masterStoreFixture{}
	ref, _ := Reference("vault-master")
	p := &MasterKeyProvisioner{reference: ref, store: store, entropy: bytes.NewReader(bytes.Repeat([]byte{91}, 32))}
	checks := 0
	got, err := p.Ensure(masterFixtureContext(t, true), func(context.Context) error { checks++; return nil })
	if err != nil || got != ref || store.creates != 1 || checks != 1 {
		t.Fatal("native provisioning failed")
	}
	if !bytes.Equal(store.submitted, make([]byte, len(store.submitted))) {
		t.Fatal("temporary native payload retained")
	}
	var stored struct {
		Key []byte `json:"key"`
	}
	if json.Unmarshal(store.material, &stored) != nil || len(stored.Key) != 32 {
		t.Fatal("incorrect stored key")
	}
	clear(stored.Key)
	got, err = p.Ensure(masterFixtureContext(t, true), func(context.Context) error { t.Fatal("existing key required creation permission"); return nil })
	if err != nil || got != ref || store.creates != 1 {
		t.Fatal("existing key changed")
	}
}
func TestNativeMasterRefusalDoesNotGenerateOrReplaceKeys(t *testing.T) {
	for _, mode := range []string{"agent", "cancelled", "custody", "metadata", "invalid-existing", "unreadable-existing", "duplicate", "lost-verification"} {
		t.Run(mode, func(t *testing.T) {
			store := &masterStoreFixture{}
			ctx := masterFixtureContext(t, mode != "agent")
			if mode == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if mode == "metadata" {
				store.existsError = true
			}
			if mode == "invalid-existing" {
				store.material = []byte(`{"key":"invalid"}`)
			}
			if mode == "unreadable-existing" {
				store.material = []byte(`{"key":"invalid"}`)
				store.readError = true
			}
			if mode == "duplicate" {
				store.duplicate = true
			}
			if mode == "lost-verification" {
				store.readError = true
			}
			before := append([]byte(nil), store.material...)
			p := &MasterKeyProvisioner{reference: "opaque-fixture-reference", store: store, entropy: bytes.NewReader(bytes.Repeat([]byte{17}, 64))}
			ref, err := p.Ensure(ctx, func(context.Context) error {
				if mode == "custody" {
					return errors.New("private-custody-canary")
				}
				return nil
			})
			if err == nil || ref != "" {
				t.Fatal("refused provisioning succeeded")
			}
			if mode != "duplicate" && mode != "lost-verification" && store.creates != 0 {
				t.Fatal("inadmissible key creation")
			}
			if mode != "lost-verification" && !bytes.Equal(before, store.material) {
				t.Fatal("existing key replaced")
			}
			if mode == "lost-verification" {
				store.readError = false
				if p.Ready(masterFixtureContext(t, true)) != nil || store.creates != 1 {
					t.Fatal("lost acknowledgement did not preserve inspectable key")
				}
			}
		})
	}
}

func TestNativeMasterReadbackRejectsDifferentKeyAndReplacedItem(t *testing.T) {
	for _, mode := range []string{"different-key", "different-item"} {
		t.Run(mode, func(t *testing.T) {
			store := &masterStoreFixture{substitute: mode == "different-key"}
			if mode == "different-item" {
				store.identity = []byte("replacement-item")
			}
			p := &MasterKeyProvisioner{reference: "fixture", store: store, entropy: bytes.NewReader(bytes.Repeat([]byte{42}, 32))}
			ref, err := p.Ensure(masterFixtureContext(t, true), func(context.Context) error { return nil })
			if !errors.Is(err, ErrMasterKeyUnavailable) || ref != "" || store.creates != 1 {
				t.Fatal("substituted readback accepted")
			}
			if string(store.readIdentity) != "synthetic-item-identity" {
				t.Fatal("readback was not pinned to created item")
			}
			if store.material == nil {
				t.Fatal("uncertain creation was removed")
			}
			if !bytes.Equal(store.submitted, make([]byte, len(store.submitted))) {
				t.Fatal("temporary material was retained")
			}
		})
	}
}

func TestMasterReaderRegistryRefusesConflictsAndNeverFallsBack(t *testing.T) {
	r := masterReaderRegistry{items: make(map[Item]masterReaderEnrollment)}
	options := MasterKeyOptions{Alias: "fixture-master", Item: Item{Service: "synthetic-master-service", Account: "fixture"}, BrokerRequirement: "synthetic-requirement"}
	store := &masterStoreFixture{material: []byte(`{"key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`)}
	p := &MasterKeyProvisioner{store: store}
	if _, err := r.enroll(options, p); err != nil {
		t.Fatal("enrollment failed")
	}
	if current, err := r.enroll(options, &MasterKeyProvisioner{}); err != nil || current != p {
		t.Fatal("identical enrollment replaced reader")
	}
	for _, mode := range []string{"requirement", "alias", "item"} {
		other := options
		switch mode {
		case "requirement":
			other.BrokerRequirement = "other"
		case "alias":
			other.Alias = "other"
		case "item":
			other.Item.Account = "other"
		}
		if _, err := r.enroll(other, &MasterKeyProvisioner{}); !errors.Is(err, ErrMasterKeyUnavailable) {
			t.Fatal("conflicting enrollment accepted")
		}
	}
	data, matched, err := r.read(context.Background(), options.Item)
	if !matched || err != nil || len(data) == 0 {
		t.Fatal("enrolled master did not use verified reader")
	}
	clear(data)
	store.existsError = true
	data, matched, err = r.read(context.Background(), options.Item)
	if !matched || !errors.Is(err, ErrMasterKeyUnavailable) || len(data) != 0 {
		t.Fatal("failed custody permitted generic fallback")
	}
	if _, matched, err = r.read(context.Background(), Item{Service: "other"}); matched || err != nil {
		t.Fatal("unrelated item dispatch changed")
	}
}

func TestRegisteredProviderUsesLaterMasterEnrollment(t *testing.T) {
	item := Item{Service: "synthetic-late-master-service", Account: "fixture"}
	genericCalls := 0
	manager, err := newManager(Options{Items: map[string]Item{"fixture-late-master": item, "fixture-other": {Service: "synthetic-unrelated", Account: "fixture"}}}, func(context.Context, Item) ([]byte, error) { genericCalls++; return []byte("synthetic-generic"), nil })
	if err != nil {
		t.Fatal(err)
	}
	options := MasterKeyOptions{Alias: "fixture-late-master", Item: item, BrokerRequirement: "fixture"}
	store := &masterStoreFixture{material: []byte(`{"key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`)}
	if _, err = masterReaders.enroll(options, &MasterKeyProvisioner{store: store}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { masterReaders.Lock(); delete(masterReaders.items, item); masterReaders.Unlock() })
	reader, err := manager.OpenURL(context.Background(), "mechanize-keychain://generic-password/fixture-late-master")
	if err != nil || reader == nil || genericCalls != 0 {
		t.Fatal("master used generic provider lookup")
	}
	reader.Close()
	store.readError = true
	if _, err = manager.OpenURL(context.Background(), "mechanize-keychain://generic-password/fixture-late-master"); !errors.Is(err, ErrMasterKeyUnavailable) || genericCalls != 0 {
		t.Fatal("custody refusal fell back to generic lookup")
	}
	reader, err = manager.OpenURL(context.Background(), "mechanize-keychain://generic-password/fixture-other")
	if err != nil || reader == nil || genericCalls != 1 {
		t.Fatal("unrelated provider lookup changed")
	}
	reader.Close()
}

type masterRefreshFixture struct {
	*masterStoreFixture
	refreshes           int
	fail, wrongIdentity bool
}

func (s *masterRefreshFixture) refreshAccess(_ context.Context, identity []byte) ([]byte, error) {
	s.refreshes++
	if s.fail {
		return nil, errors.New("private-refresh-canary")
	}
	s.readError = false
	if s.wrongIdentity {
		return []byte("different-item"), nil
	}
	return append([]byte(nil), identity...), nil
}
func TestNativeMasterAccessRefreshRequiresExplicitSetupAndSameItem(t *testing.T) {
	for _, mode := range []string{"ready", "repair", "notNative", "failedRepair", "differentItem", "invalidKey"} {
		t.Run(mode, func(t *testing.T) {
			material, _ := json.Marshal(struct {
				Key []byte `json:"key"`
			}{bytes.Repeat([]byte{7}, 32)})
			if mode == "invalidKey" {
				material = []byte(`{"key":"invalid"}`)
			}
			store := &masterRefreshFixture{masterStoreFixture: &masterStoreFixture{material: material, readError: mode != "ready" && mode != "invalidKey"}, fail: mode == "failedRepair", wrongIdentity: mode == "differentItem"}
			original := append([]byte(nil), material...)
			p := &MasterKeyProvisioner{reference: "opaque-reference", store: store, entropy: bytes.NewReader(make([]byte, 32))}
			_ = p.Ready(masterFixtureContext(t, true))
			if store.refreshes != 0 {
				t.Fatal("readiness changed access")
			}
			got, err := p.Ensure(masterFixtureContext(t, mode != "notNative"), func(context.Context) error { t.Fatal("existing key replacement attempted"); return nil })
			expected := mode == "ready" || mode == "repair"
			if (err == nil) != expected || expected && got != "opaque-reference" {
				t.Fatal("unexpected repair result")
			}
			calls := 0
			if mode == "repair" || mode == "failedRepair" || mode == "differentItem" {
				calls = 1
			}
			if store.refreshes != calls || store.creates != 0 || !bytes.Equal(store.material, original) {
				t.Fatal("repair replayed, replaced or changed existing key")
			}
		})
	}
}
