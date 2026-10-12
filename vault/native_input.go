package vault

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/viant/mechanize/auth"
)

var ErrNativeInput = errors.New("native vault input rejected")
var ErrNativeOutcomeUnknown = errors.New("native vault administration outcome requires inspection")
var nativeInputMagic = [8]byte{'M', 'V', 'L', 'T', 0, 0, 0, 1}

// NativeEntryProtection is a trusted host adapter, never a caller-supplied flag.
// It must hold qualified whole-window AX/capture/recording suppression throughout
// action and release it only after action returns. Failure closes the channel.
type NativeEntryProtection interface {
	WithEntry(context.Context, Target, func() error) error
}

// NativeInputService belongs only on a signed, authenticated native-human
// transport. It has no MCP registration or generic JSON request representation.
// The transport must bound read deadlines and close its write half after one
// frame; EOF is part of the closed single-frame protocol.
type NativeInputService struct {
	store      *Store
	protection NativeEntryProtection
}

// ExposureGate identifies the exact shared gate for host exposure admission.
// A production host must reject a provider without this shared gate; custom
// fixture protection adapters do not imply complete capture suppression.
func (s *NativeInputService) ExposureGate() *ExposureGate {
	if s == nil {
		return nil
	}
	gate, _ := s.protection.(*ExposureGate)
	return gate
}

func NewNativeInputService(store *Store, protection NativeEntryProtection) (*NativeInputService, error) {
	if store == nil || protection == nil {
		return nil, ErrUnavailable
	}
	return &NativeInputService{store: store, protection: protection}, nil
}
func (s *NativeInputService) Ready(ctx context.Context) error {
	if !auth.NativeHuman(ctx) {
		return auth.ErrUnauthorized
	}
	if s == nil || s.store == nil {
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
func (s *NativeInputService) Inventory(ctx context.Context) ([]InventoryEntry, error) {
	if s == nil || s.store == nil {
		return nil, ErrUnavailable
	}
	return s.store.Inventory(ctx)
}
func (s *NativeInputService) Create(ctx context.Context, target Target, input io.Reader) (Reference, error) {
	return s.submit(ctx, target, "", false, input)
}
func (s *NativeInputService) Update(ctx context.Context, target Target, revision string, input io.Reader) (Reference, error) {
	if !auth.NativeHuman(ctx) {
		return Reference{}, auth.ErrUnauthorized
	}
	if !nativeRevision(revision) {
		return Reference{}, ErrConflict
	}
	return s.submit(ctx, target, revision, true, input)
}

func nativeRevision(revision string) bool {
	decoded, err := hex.DecodeString(revision)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == revision
}

func (s *NativeInputService) Delete(ctx context.Context, target Target, revision string) error {
	if !auth.NativeHuman(ctx) {
		return auth.ErrUnauthorized
	}
	if _, _, err := scoped(ctx, target); err != nil {
		return err
	}
	if !nativeRevision(revision) {
		return ErrConflict
	}
	if s == nil || s.store == nil || s.protection == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	called, started := false, false
	err := s.protection.WithEntry(ctx, target, func() error {
		if called || ctx.Err() != nil {
			return ErrUnavailable
		}
		called = true
		started = true
		return s.store.Delete(ctx, target, revision)
	})
	if err != nil {
		if started {
			return ErrNativeOutcomeUnknown
		}
		return ErrUnavailable
	}
	if !called {
		return ErrUnavailable
	}
	return nil
}
func (s *NativeInputService) submit(ctx context.Context, target Target, revision string, update bool, input io.Reader) (Reference, error) {
	if !auth.NativeHuman(ctx) {
		return Reference{}, auth.ErrUnauthorized
	}
	if _, _, err := scoped(ctx, target); err != nil {
		return Reference{}, err
	}
	if ctx.Err() != nil || input == nil || s == nil || s.store == nil || s.protection == nil {
		return Reference{}, ErrUnavailable
	}
	var result Reference
	called, administrationStarted := false, false
	err := s.protection.WithEntry(ctx, target, func() error {
		if called || ctx.Err() != nil {
			return ErrUnavailable
		}
		called = true
		if s.Ready(ctx) != nil {
			return ErrUnavailable
		}
		secret, err := readNativeInput(input)
		if err != nil {
			return ErrNativeInput
		}
		defer secret.clear()
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		administrationStarted = true
		if update {
			result, err = s.store.Update(ctx, target, revision, secret.username, secret.password)
		} else {
			result, err = s.store.Create(ctx, target, secret.username, secret.password)
		}
		return err
	})
	if err != nil {
		// Transport/protection errors must not carry request bytes. After beginning
		// administration, an acknowledgement failure must not invite an input replay.
		if administrationStarted {
			return Reference{}, ErrNativeOutcomeUnknown
		}
		if errors.Is(err, ErrNativeInput) {
			return Reference{}, ErrNativeInput
		}
		return Reference{}, ErrUnavailable
	}
	if !called || result.ResourceURL == "" {
		return Reference{}, ErrUnavailable
	}
	return result, nil
}

// Credentials never implement JSON or printable byte-bearing representations.
// Only this package can access the decoded buffers; every failure wipes them.
type nativeInput struct{ username, password []byte }

func (n *nativeInput) clear()                     { clear(n.username); clear(n.password) }
func (nativeInput) MarshalJSON() ([]byte, error)  { return nil, ErrNativeInput }
func (nativeInput) String() string                { return "[native vault input withheld]" }
func (nativeInput) GoString() string              { return "[native vault input withheld]" }
func (nativeInput) Format(s fmt.State, verb rune) { s.Write([]byte("[native vault input withheld]")) }

var _ json.Marshaler = nativeInput{}

func readNativeInput(reader io.Reader) (nativeInput, error) {
	var header [16]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil || !bytes.Equal(header[:8], nativeInputMagic[:]) {
		return nativeInput{}, ErrNativeInput
	}
	u, p := binary.BigEndian.Uint32(header[8:12]), binary.BigEndian.Uint32(header[12:16])
	if u == 0 || p == 0 || uint64(u)+uint64(p) > maxCredentialBytes {
		return nativeInput{}, ErrNativeInput
	}
	result := nativeInput{username: make([]byte, int(u)), password: make([]byte, int(p))}
	accepted := false
	defer func() {
		if !accepted {
			result.clear()
		}
	}()
	if _, err := io.ReadFull(reader, result.username); err != nil {
		return nativeInput{}, ErrNativeInput
	}
	if _, err := io.ReadFull(reader, result.password); err != nil {
		return nativeInput{}, ErrNativeInput
	}
	var extra [1]byte
	if n, err := io.ReadFull(reader, extra[:]); n != 0 || err != io.EOF {
		clear(extra[:])
		return nativeInput{}, ErrNativeInput
	}
	if !utf8.Valid(result.username) || !utf8.Valid(result.password) || bytes.ContainsRune(result.username, 0) || bytes.ContainsRune(result.password, 0) {
		return nativeInput{}, ErrNativeInput
	}
	accepted = true
	return result, nil
}
