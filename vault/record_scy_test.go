package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/viant/scy/cred"
)

func scyFixtureFields(kind string, payload string) [][2][]byte {
	return [][2][]byte{{[]byte(scyTypeField), []byte(kind)}, {[]byte(scyPayloadField), []byte(payload)}}
}
func TestScyTypedTargetsUsePinnedPrimitivesWithoutSideEffects(t *testing.T) {
	fixtures := map[string]string{
		"sha1":        `{"Key":"key-canary","IntegrityKey":"integrity-canary"}`,
		"aws":         `{"Key":"id-canary","Secret":"secret-canary","Region":"region"}`,
		"azure":       `{"ClientID":"client-canary","ClientSecret":"secret-canary","TenantID":"tenant"}`,
		"ssh":         `{"Username":"user-canary","PrivateKeyPath":"/must-not-read/key","PrivateKeyPassword":"secret-canary"}`,
		"generic":     `{"Username":"user-canary","Password":"secret-canary"}`,
		"jwt":         `{"client_email":"client-canary","private_key":"secret-canary","token_uri":"https://must-not-request.invalid"}`,
		"oauth2":      `{"ClientID":"client-canary","ClientSecret":"secret-canary","Endpoint":{"AuthURL":"https://must-not-request.invalid"},"Scopes":["scope"]}`,
		"certificate": `{"CertificatePath":"/must-not-read/certificate","PrivateKeyPath":"/must-not-read/key"}`,
		"x509":        `{"CertificatePEM":"Y2VydC1jYW5hcnk=","PrivateKeyPEM":"a2V5LWNhbmFyeQ=="}`,
	}
	for kind, payload := range fixtures {
		t.Run(kind, func(t *testing.T) {
			target, e := cred.TargetType(kind)
			if e != nil || target == nil {
				t.Fatal("Scy target unavailable")
			}
			fields := scyFixtureFields(kind, payload)
			values, e := NewRecordValues([]byte("typed-key"), fields)
			if e != nil {
				t.Fatalf("typed validation: %v", e)
			}
			plain, e := values.take()
			if e != nil {
				t.Fatal(e)
			}
			defer clear(plain)
			if _, e = recordCredentials(plain); e == nil {
				t.Fatal("non-basic type admitted to browser delivery")
			}
			for _, field := range fields {
				for _, b := range field[1] {
					if b != 0 {
						t.Fatal("owned type/payload buffer retained")
					}
				}
			}
		})
	}
}
func TestScyFlatPrimitivesAndBasicDeliveryAreBackwardCompatible(t *testing.T) {
	for _, fields := range [][][2][]byte{
		{{[]byte(scyTypeField), []byte("raw")}, {[]byte("secret"), {0, 255, 1}}},
		{{[]byte(scyTypeField), []byte("key")}, {[]byte("Key"), []byte("key-canary")}, {[]byte("Secret"), []byte("secret-canary")}},
		{{[]byte(scyTypeField), []byte("basic")}, {[]byte("username"), []byte("user-canary")}, {[]byte("password"), []byte("pass-canary")}, {[]byte("email"), []byte("email-canary")}},
	} {
		v, e := NewRecordValues([]byte("key"), fields)
		if e != nil {
			t.Fatal(e)
		}
		plain, e := v.take()
		if e != nil {
			t.Fatal(e)
		}
		defer clear(plain)
		_, parsed, e := parseRecord(plain)
		if e != nil {
			t.Fatal(e)
		}
		if string(scyField(parsed, scyTypeField)) == "basic" {
			c, e := recordCredentials(plain)
			if e != nil || string(c.username) != "user-canary" || string(c.password) != "pass-canary" {
				t.Fatal("basic pair unavailable")
			}
			// Installed pre-adapter brokers read these same lowercase fields and ignore
			// metadata; no new binary format or duplicate JSON credential is needed.
			if string(scyField(parsed, "username")) != "user-canary" || len(scyField(parsed, scyPayloadField)) != 0 {
				t.Fatal("legacy reader compatibility lost")
			}
		} else if _, e := recordCredentials(plain); e == nil {
			t.Fatal("non-basic primitive delivered")
		}
	}
}
func TestScyInvalidTypesPayloadsAndMixedRepresentationsRefuseAndErase(t *testing.T) {
	cases := [][][2][]byte{
		scyFixtureFields("private-type-canary", `{}`), scyFixtureFields("jwt", `{"private_key":"secret-canary","private_key":"other"}`),
		scyFixtureFields("jwt", `{"private_key":"secret-canary","PRIVATE_KEY":"other"}`), scyFixtureFields("jwt", `{"private_key":9}`), scyFixtureFields("aws", `{"Secret":"one-canary","ſecret":"two-canary"}`),
		scyFixtureFields("jwt", `{"Unknown":"secret-canary"}`), scyFixtureFields("jwt", `{} {}`), scyFixtureFields("jwt", `null`), scyFixtureFields("jwt", `{}`),
		scyFixtureFields("basic", `{"Username":"user-canary","Password":"pass-canary"}`),
		{{[]byte(scyPayloadField), []byte(`{"secret":"secret-canary"}`)}},
		{{[]byte(scyTypeField), []byte("basic")}, {[]byte("username"), []byte("user-canary")}, {[]byte("password"), []byte("pass-canary")}, {[]byte("secret"), []byte("ambiguous-canary")}},
	}
	for _, fields := range cases {
		key := []byte("key-canary")
		v, e := NewRecordValues(key, fields)
		if e != ErrRecord {
			t.Fatal("invalid typed record accepted")
		}
		if strings.Contains(fmt.Sprintf("%+v %v", v, e), "canary") {
			t.Fatal("error formatted plaintext")
		}
		for _, b := range key {
			if b != 0 {
				t.Fatal("key retained")
			}
		}
		for _, field := range fields {
			for _, b := range append(field[0], field[1]...) {
				if b != 0 {
					t.Fatal("invalid owned fields retained")
				}
			}
		}
	}
}
func TestTypedBasicUsesActualPrivateRevisionConsumerAndWipes(t *testing.T) {
	r, human, ctx, b, _, _ := recordDeliveryFixture(t)
	values, e := NewRecordValues([]byte("typed-basic-key"), [][2][]byte{{[]byte(scyTypeField), []byte("basic")}, {[]byte("username"), []byte("typed-user-canary")}, {[]byte("password"), []byte("typed-pass-canary")}})
	if e != nil {
		t.Fatal(e)
	}
	meta, e := r.Create(human, values)
	if e != nil {
		t.Fatal(e)
	}
	ciphertext, readErr := os.ReadFile(filepath.Join(r.store.path, meta.Reference.ID+".record"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, value := range []string{"typed-user-canary", "typed-pass-canary", "typed-basic-key", scyTypeField, "basic"} {
		if bytes.Contains(ciphertext, []byte(value)) {
			t.Fatal("typed plaintext visible on disk")
		}
	}
	delivery, e := ApproveRecordDelivery(human, ctx, r, b.Target, meta, time.Now().Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	manager, e := NewRecordDeliveryManager(delivery, func(_ context.Context, actual Binding) (Binding, error) { return actual, nil })
	if e != nil {
		t.Fatal(e)
	}
	var retainedUser, retainedPass []byte
	e = delivery.UseBinding(ctx, b, func(ref Reference, revision string) error {
		return manager.ConsumeRevision(ctx, b, ref, revision, func(c Credentials) error {
			return c.WithBytes(func(user, pass []byte) error {
				if string(user) != "typed-user-canary" || string(pass) != "typed-pass-canary" {
					t.Fatal("typed basic mismatch")
				}
				retainedUser = user
				retainedPass = pass
				return nil
			})
		})
	})
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range append(retainedUser, retainedPass...) {
		if v != 0 {
			t.Fatal("delivery bytes not wiped")
		}
	}
	output, _ := json.Marshal(meta)
	if strings.Contains(string(output), "canary") || strings.Contains(fmt.Sprintf("%+v", delivery), "canary") {
		t.Fatal("public metadata leaked secret")
	}
	// Replacing the ciphertext invalidates the original sealed selection.
	next, _ := NewRecordValues([]byte("typed-basic-key"), [][2][]byte{{[]byte("username"), []byte("new")}, {[]byte("password"), []byte("new")}})
	if _, e = r.Update(human, meta.Reference, meta.Revision, next); e != nil {
		t.Fatal(e)
	}
	e = delivery.UseBinding(ctx, b, func(ref Reference, rev string) error {
		return manager.ConsumeRevision(ctx, b, ref, rev, func(Credentials) error { t.Fatal("stale revision used"); return nil })
	})
	if e == nil {
		t.Fatal("stale typed binding accepted")
	}
}
