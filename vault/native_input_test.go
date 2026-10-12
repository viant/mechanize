package vault

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

type fixtureProtection struct {
	deny, failAfter bool
	calls           int
}

func (p *fixtureProtection) WithEntry(ctx context.Context, target Target, action func() error) error {
	p.calls++
	if p.deny {
		return errors.New("fixture-private-error-canary")
	}
	if err := action(); err != nil {
		return err
	}
	if p.failAfter {
		return errors.New("fixture-private-error-canary")
	}
	return nil
}

type countingNativeReader struct {
	reads  int
	reader io.Reader
}

func (r *countingNativeReader) Read(p []byte) (int, error) { r.reads++; return r.reader.Read(p) }
func fixtureNativeFrame(user, pass []byte) []byte {
	b := make([]byte, 16)
	copy(b, nativeInputMagic[:])
	binary.BigEndian.PutUint32(b[8:12], uint32(len(user)))
	binary.BigEndian.PutUint32(b[12:16], uint32(len(pass)))
	b = append(b, user...)
	return append(b, pass...)
}
func TestNativeInputBoundaryRejectsBeforeAnyCredentialRead(t *testing.T) {
	store := fixtureStore(t)
	guard := &fixtureProtection{}
	service, err := NewNativeInputService(store, guard)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"agent", "protection", "scope", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx := fixtureContext("native-input-fixture", mode != "agent")
			target := fixtureBinding().Target
			guard.deny = mode == "protection"
			if mode == "scope" {
				target.Origin = "https://example.test/path"
			}
			if mode == "cancelled" {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			reader := &countingNativeReader{reader: bytes.NewReader(fixtureNativeFrame([]byte("fixture-user"), []byte("fixture-password")))}
			if _, err := service.Create(ctx, target, reader); err == nil || strings.Contains(err.Error(), "canary") {
				t.Fatal("unsafe admission or error leak")
			}
			if reader.reads != 0 {
				t.Fatal("credentials read before admission/protection")
			}
		})
	}
}
func TestNativeInputCreatesUpdatesAndReturnsOnlyOpaqueReference(t *testing.T) {
	store := fixtureStore(t)
	guard := &fixtureProtection{}
	service, _ := NewNativeInputService(store, guard)
	ctx := fixtureContext("native-input-fixture", true)
	target := fixtureBinding().Target
	ref, err := service.Create(ctx, target, bytes.NewReader(fixtureNativeFrame([]byte("fixture-user"), []byte("fixture-password"))))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(ref)
	if strings.Contains(string(raw), "fixture-user") || strings.Contains(string(raw), "fixture-password") {
		t.Fatal("secret in public result")
	}
	meta, err := store.Metadata(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Update(ctx, target, meta.Revision, bytes.NewReader(fixtureNativeFrame([]byte("fixture-user-2"), []byte("fixture-password-2")))); err != nil {
		t.Fatal(err)
	}
	if guard.calls != 2 {
		t.Fatal("protection lease missing")
	}
}
func TestNativeInputLostAcknowledgementIsUnknownAndMustNotReplay(t *testing.T) {
	store := fixtureStore(t)
	guard := &fixtureProtection{failAfter: true}
	service, _ := NewNativeInputService(store, guard)
	ctx := fixtureContext("native-input-fixture", true)
	target := fixtureBinding().Target
	_, err := service.Create(ctx, target, bytes.NewReader(fixtureNativeFrame([]byte("fixture-user"), []byte("fixture-password"))))
	if !errors.Is(err, ErrNativeOutcomeUnknown) || strings.Contains(err.Error(), "canary") {
		t.Fatal("unknown outcome was hidden or leaked")
	}
	if _, err = store.Metadata(ctx, target); err != nil {
		t.Fatal("committed entry not inspectable", err)
	}
}
func TestNativeInputDecoderRejectsOpenEndedMalformedAndOversizedFrames(t *testing.T) {
	valid := fixtureNativeFrame([]byte("fixture-user"), []byte("fixture-password"))
	oversized := append([]byte(nil), valid[:16]...)
	binary.BigEndian.PutUint32(oversized[8:12], 0xffffffff)
	binary.BigEndian.PutUint32(oversized[12:16], 0xffffffff)
	wrongVersion := append([]byte(nil), valid...)
	wrongVersion[7] = 2
	for _, frame := range [][]byte{valid[:15], valid[:len(valid)-1], append(append([]byte(nil), valid...), 0), oversized, wrongVersion, fixtureNativeFrame(nil, []byte("x")), fixtureNativeFrame([]byte{0xff}, []byte("x")), fixtureNativeFrame([]byte("x"), []byte{0})} {
		if _, err := readNativeInput(bytes.NewReader(frame)); !errors.Is(err, ErrNativeInput) {
			t.Fatal("malformed frame accepted")
		}
	}
	secret, err := readNativeInput(bytes.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.clear()
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		if strings.Contains(fmt.Sprintf(format, secret), "fixture-user") {
			t.Fatal("secret formatting leak")
		}
	}
	if _, err = json.Marshal(secret); err == nil {
		t.Fatal("secret JSON serialization enabled")
	}
}

func TestNativeInputGoldenFrameMatchesSwiftEncoder(t *testing.T) {
	frame := []byte{77, 86, 76, 84, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 97, 206, 178}
	secret, err := readNativeInput(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.clear()
	if !bytes.Equal(secret.username, []byte{97}) || !bytes.Equal(secret.password, []byte{206, 178}) {
		t.Fatal("cross-language frame mismatch")
	}
}
func TestNativeInputDeletionUsesProtectionAndRevision(t *testing.T) {
	store := fixtureStore(t)
	guard := &fixtureProtection{}
	service, _ := NewNativeInputService(store, guard)
	ctx := fixtureContext("native-delete-fixture", true)
	target := fixtureBinding().Target
	if _, err := service.Create(ctx, target, bytes.NewReader(fixtureNativeFrame([]byte("fixture-user"), []byte("fixture-password")))); err != nil {
		t.Fatal(err)
	}
	meta, err := store.Metadata(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.Delete(ctx, target, meta.Revision); err != nil {
		t.Fatal(err)
	}
	if guard.calls != 2 {
		t.Fatal("delete did not acquire protection")
	}
	if _, err = store.Metadata(ctx, target); !errors.Is(err, ErrMissing) {
		t.Fatal("entry not deleted")
	}
}
