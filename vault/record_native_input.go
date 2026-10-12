package vault

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"

	"github.com/viant/mechanize/auth"
)

// NativeRecordEntryOrigin is only a protected native-entry lifecycle binding.
// It is neither part of record identity nor authority to use a secret at a site.
const NativeRecordEntryOrigin = "https://vault.mechanize.invalid"

// NativeRecordInputService is a source-only signed-native administration
// boundary. The host must enroll the exact same ExposureGate used by every
// exposure path; accepting a fixture adapter does not qualify production entry.
// No MCP method, secret consumption operation, or transport is registered here.
// The native transport must bound I/O deadlines and close after one MVLT v2
// frame. Target contains only public lifecycle metadata, never record key,
// field names or values. Its opaque account token must be generated independently
// of those secrets by the trusted entry lifecycle.
type NativeRecordInputService struct {
	store      *RecordStore
	protection NativeEntryProtection
}

func NewNativeRecordInputService(store *RecordStore, protection NativeEntryProtection) (*NativeRecordInputService, error) {
	if store == nil || store.store == nil || protection == nil {
		return nil, ErrUnavailable
	}
	if gate, ok := protection.(*ExposureGate); ok && gate == nil {
		return nil, ErrUnavailable
	}
	return &NativeRecordInputService{store: store, protection: protection}, nil
}

// ExposureGate never treats a caller flag or arbitrary adapter as proof that
// native-entry protection participates in the host's shared exposure gate.
func (s *NativeRecordInputService) ExposureGate() *ExposureGate {
	if s == nil {
		return nil
	}
	gate, _ := s.protection.(*ExposureGate)
	return gate
}
func (s *NativeRecordInputService) Ready(ctx context.Context) error {
	if !auth.NativeHuman(ctx) {
		return auth.ErrUnauthorized
	}
	if s == nil || s.store == nil || s.store.store == nil || s.protection == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	readiness, ok := s.store.store.cipher.(interface {
		Ready(context.Context, string) error
	})
	if !ok || readiness.Ready(ctx, s.store.store.version) != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

// Inventory returns opaque metadata only; RecordStore keeps names and values
// encrypted and clears internal decrypted validation buffers.
func (s *NativeRecordInputService) Inventory(ctx context.Context) ([]RecordMetadata, error) {
	if err := s.Ready(ctx); err != nil {
		return nil, err
	}
	return s.store.Inventory(ctx)
}
func validRecordEntryTarget(target Target) bool {
	if target.Origin != NativeRecordEntryOrigin || target.Validate() != nil {
		return false
	}
	if nativeRevision(target.Account) {
		return true
	}
	// Preserve the existing trusted native lifecycle's public account-UUID form.
	if !strings.HasPrefix(target.Account, "account-") {
		return false
	}
	uuid := strings.TrimPrefix(target.Account, "account-")
	if len(uuid) != 36 || uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(uuid, "-", "")
	decoded, err := hex.DecodeString(compact)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == compact
}
func (s *NativeRecordInputService) admit(ctx context.Context, target Target) error {
	if !auth.NativeHuman(ctx) {
		return auth.ErrUnauthorized
	}
	if !validRecordEntryTarget(target) {
		return ErrScope
	}
	if s == nil || s.store == nil || s.store.store == nil || s.protection == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

type nativeRecordCall struct {
	started bool
	result  RecordMetadata
}

// protect admits exactly one synchronous action. Track the callback's result
// independently: an adapter that swallows an error, skips or repeats a callback
// cannot turn rejection into success. Closed callbacks cannot read or mutate.
// Production uses ExposureGate, whose WithEntry holds the lease through action;
// custom adapters are trusted-only fixtures and must honor that same contract.
func (s *NativeRecordInputService) protect(ctx context.Context, target Target, action func(*nativeRecordCall) error) (RecordMetadata, error) {
	var mu sync.Mutex
	calls := 0
	closed, completed := false, false
	var call nativeRecordCall
	var actionErr error
	protectionErr := s.protection.WithEntry(ctx, target, func() error {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if closed || calls != 1 {
			return ErrUnavailable
		}
		defer func() { completed = true }()
		if s.Ready(ctx) != nil {
			actionErr = ErrUnavailable
			return actionErr
		}
		actionErr = action(&call)
		return actionErr
	})
	mu.Lock()
	defer mu.Unlock()
	closed = true
	if calls != 1 || !completed || protectionErr != nil || actionErr != nil || ctx.Err() != nil {
		if call.started {
			return RecordMetadata{}, ErrNativeOutcomeUnknown
		}
		// Never propagate arbitrary protection, transport or cipher diagnostics.
		for _, safe := range []error{ErrNativeInput, ErrConflict, ErrMissing, ErrRecord, ErrNativeOutcomeUnknown} {
			if errors.Is(actionErr, safe) {
				return RecordMetadata{}, safe
			}
		}
		return RecordMetadata{}, ErrUnavailable
	}
	return call.result, nil
}
func (s *NativeRecordInputService) Create(ctx context.Context, target Target, input io.Reader) (RecordMetadata, error) {
	return s.submit(ctx, target, RecordReference{}, "", false, input)
}
func (s *NativeRecordInputService) Update(ctx context.Context, target Target, ref RecordReference, revision string, input io.Reader) (RecordMetadata, error) {
	return s.submit(ctx, target, ref, revision, true, input)
}
func (s *NativeRecordInputService) submit(ctx context.Context, target Target, ref RecordReference, revision string, update bool, input io.Reader) (RecordMetadata, error) {
	if err := s.admit(ctx, target); err != nil {
		return RecordMetadata{}, err
	}
	if update {
		if !nativeRevision(ref.ID) {
			return RecordMetadata{}, ErrRecord
		}
		if !nativeRevision(revision) {
			return RecordMetadata{}, ErrConflict
		}
	}
	if input == nil {
		return RecordMetadata{}, ErrUnavailable
	}
	return s.protect(ctx, target, func(call *nativeRecordCall) error {
		if update {
			// Ref ownership and revision are admitted before reading any incoming
			// secrets. The Store repeats CAS atomically after the frame is decoded.
			meta, err := s.store.Metadata(ctx, ref)
			if err != nil {
				return err
			}
			if meta.Revision != revision {
				return ErrConflict
			}
		}
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		values, err := readRecordFrame(input)
		if err != nil {
			return ErrNativeInput
		}
		defer values.Destroy() // Executes while WithEntry still holds protection.
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		call.started = true
		if update {
			call.result, err = s.store.Update(ctx, ref, revision, values)
		} else {
			call.result, err = s.store.Create(ctx, values)
		}
		if err != nil {
			return err
		}
		if !nativeRevision(call.result.Reference.ID) || !nativeRevision(call.result.Revision) {
			return ErrUnavailable
		}
		return nil
	})
}
func (s *NativeRecordInputService) Delete(ctx context.Context, target Target, ref RecordReference, revision string) error {
	if err := s.admit(ctx, target); err != nil {
		return err
	}
	if !nativeRevision(ref.ID) {
		return ErrRecord
	}
	if !nativeRevision(revision) {
		return ErrConflict
	}
	_, err := s.protect(ctx, target, func(call *nativeRecordCall) error {
		meta, err := s.store.Metadata(ctx, ref)
		if err != nil {
			return err
		}
		if meta.Revision != revision {
			return ErrConflict
		}
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		call.started = true
		return s.store.Delete(ctx, ref, revision)
	})
	return err
}
