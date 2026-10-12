//go:build darwin || linux

package keychain

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Trusted bootstrap must bind options, session, exact helper identity, parent
// authority and approval attestation before returning this private child.
type migrationWorkerLauncher func(context.Context, migrationOptions, []byte) (*migrationChildProcess, error)
type migrationProcessBackend struct {
	options migrationOptions
	launch  migrationWorkerLauncher
}
type migrationRemotePreparation struct {
	mu        sync.Mutex
	child     *migrationChildProcess
	options   migrationOptions
	identity  []byte
	checked   bool
	attempted bool
	disposed  bool
}

func (h *migrationRemotePreparation) dispose() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.disposed {
		return
	}
	h.disposed = true
	h.child.close()
	wait, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = h.child.waitStopped(wait)
}
func newMigrationProcessBackend(options migrationOptions, launch migrationWorkerLauncher) (*migrationProcessBackend, error) {
	if !validMigrationOptions(options) || launch == nil {
		return nil, errMigrationUnavailable
	}
	return &migrationProcessBackend{options, launch}, nil
}
func migrationProxyRequest(child *migrationChildProcess, op string) (migrationWorkerRequest, error) {
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return migrationWorkerRequest{}, errMigrationUnavailable
	}
	return migrationWorkerRequest{Version: 1, ID: hex.EncodeToString(id[:]), Session: child.session, Operation: op}, nil
}
func migrationProxyExchange(ctx context.Context, child *migrationChildProcess, op string) (migrationWorkerResponse, error) {
	request, err := migrationProxyRequest(child, op)
	if err != nil {
		return migrationWorkerResponse{}, err
	}
	response, err := child.exchange(ctx, request)
	if err != nil {
		return migrationWorkerResponse{}, err
	}
	if response.Status == "unknown" {
		return migrationWorkerResponse{}, errMigrationUnknown
	}
	if response.Status == "unavailable" {
		return migrationWorkerResponse{}, errMigrationUnavailable
	}
	return response, nil
}
func (b *migrationProcessBackend) prepare(ctx context.Context, options migrationOptions) (*migrationPrepared, error) {
	if migrationContext(ctx) != nil || b == nil || options != b.options {
		return nil, errMigrationUnavailable
	}
	child, err := b.launch(ctx, options, nil)
	if err != nil || child == nil {
		if child != nil {
			child.close()
		}
		return nil, errMigrationUnavailable
	}
	response, err := migrationProxyExchange(ctx, child, "prepare")
	if err != nil || response.Status != "prepared" || !validMasterIdentity(response.Identity) {
		child.close()
		return nil, errMigrationUnavailable
	}
	h := &migrationRemotePreparation{child: child, options: options, identity: bytes.Clone(response.Identity)}
	return &migrationPrepared{identity: bytes.Clone(response.Identity), handle: h, dispose: h.dispose}, nil
}
func migrationProxyHandle(prepared *migrationPrepared, options migrationOptions) (*migrationRemotePreparation, error) {
	if prepared == nil || !validMasterIdentity(prepared.identity) {
		return nil, errMigrationUnavailable
	}
	h, ok := prepared.handle.(*migrationRemotePreparation)
	if !ok || h == nil || h.child == nil || h.options != options || !bytes.Equal(h.identity, prepared.identity) {
		return nil, errMigrationUnavailable
	}
	return h, nil
}
func (b *migrationProcessBackend) verifyBeforeCommit(ctx context.Context, options migrationOptions, prepared *migrationPrepared) error {
	if migrationContext(ctx) != nil || b == nil || options != b.options {
		return errMigrationUnavailable
	}
	h, err := migrationProxyHandle(prepared, options)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.disposed || h.attempted || h.checked {
		return errMigrationUnavailable
	}
	response, err := migrationProxyExchange(ctx, h.child, "verify")
	if err != nil || response.Status != "checked" {
		return errMigrationUnavailable
	}
	h.checked = true
	return nil
}
func (b *migrationProcessBackend) commit(ctx context.Context, options migrationOptions, prepared *migrationPrepared) error {
	if migrationContext(ctx) != nil || b == nil || options != b.options {
		return errMigrationUnavailable
	}
	h, err := migrationProxyHandle(prepared, options)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.disposed || h.attempted || !h.checked {
		return errMigrationUnavailable
	}
	h.attempted = true
	response, err := migrationProxyExchange(ctx, h.child, "commit")
	if err != nil || response.Status != "verified" {
		return errMigrationUnknown
	}
	return nil
}
func (b *migrationProcessBackend) inspect(ctx context.Context, options migrationOptions, identity []byte) (migrationInspection, error) {
	if migrationContext(ctx) != nil || b == nil || options != b.options || !validMasterIdentity(identity) {
		return migrationInspection{}, errMigrationUnavailable
	}
	child, err := b.launch(ctx, options, bytes.Clone(identity))
	if err != nil || child == nil {
		if child != nil {
			child.close()
		}
		return migrationInspection{}, errMigrationUnavailable
	}
	defer child.close()
	response, err := migrationProxyExchange(ctx, child, "inspect")
	if err != nil || response.Status != "verified" {
		return migrationInspection{}, errMigrationUnavailable
	}
	// Trusted bootstrap bound the expected item reference; the worker may report
	// verified only after fresh same-item/full-new-policy inspection.
	return migrationInspection{identity: bytes.Clone(identity), exactNewPolicy: true}, nil
}

var _ migrationBackend = (*migrationProcessBackend)(nil)
