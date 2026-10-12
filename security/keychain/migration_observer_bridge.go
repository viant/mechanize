//go:build darwin || linux

package keychain

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"time"
)

const migrationObserverLimit = 16384

type migrationObserverRequest struct {
	Version                  int    `json:"version"`
	Nonce                    string `json:"nonce"`
	Session                  string `json:"session"`
	ManifestSHA256           string `json:"manifestSHA256"`
	DeadlineUnixMilliseconds int64  `json:"deadlineUnixMilliseconds"`
	Mode                     string `json:"mode,omitempty"`
}
type migrationObserverResponse struct {
	Version                    int      `json:"version"`
	Nonce                      string   `json:"nonce"`
	Session                    string   `json:"session"`
	ManifestSHA256             string   `json:"manifestSHA256"`
	RequestSHA256              string   `json:"requestSHA256"`
	ObservedAtUnixMilliseconds int64    `json:"observedAtUnixMilliseconds"`
	SourceReceiptSHA256        string   `json:"sourceReceiptSHA256"`
	LoadedExtensionPath        string   `json:"loadedExtensionPath"`
	ExtensionID                string   `json:"extensionID"`
	StorageSHA256              string   `json:"storageSHA256,omitempty"`
	StoppedExecutables         []string `json:"stoppedExecutables"`
	OldConsoleRequirement      string   `json:"oldConsoleRequirement"`
	OldConsoleBirth            string   `json:"oldConsoleBirth"`
	Mode                       string   `json:"mode,omitempty"`
}

type migrationAuthenticatedObserver struct {
	mu                      sync.Mutex
	authority               *migrationNativeAuthority
	session, manifest, mode string
	count                   int
	// Bound to the local, successfully verified candidate-console diagnostic.
	// The console channel cannot provide or replace this proof.
	readiness func(context.Context) (migrationRuntimeTerminalEvidence, error)
}

func newMigrationAuthenticatedObserver(a *migrationNativeAuthority, session, manifest string, modes ...string) (*migrationAuthenticatedObserver, error) {
	if a == nil || !validMigrationID(session) || !validMigrationID(manifest) {
		return nil, errMigrationUnavailable
	}
	m := ""
	if len(modes) > 1 {
		return nil, errMigrationUnavailable
	}
	if len(modes) == 1 {
		m = modes[0]
	}
	if m != "" && m != preserveExtensionMode && !unifiedRuntimeMode(m) {
		return nil, errMigrationUnavailable
	}
	return &migrationAuthenticatedObserver{authority: a, session: session, manifest: manifest, mode: m}, nil
}
func observerWriteFrame(w io.Writer, marker string, payload []byte) error {
	if len(marker) != 8 || len(payload) == 0 || len(payload) > migrationObserverLimit {
		return errMigrationUnavailable
	}
	header := make([]byte, 12)
	copy(header, marker)
	binary.BigEndian.PutUint32(header[8:], uint32(len(payload)))
	if migrationWriteAll(w, header) != nil || migrationWriteAll(w, payload) != nil {
		return errMigrationUnavailable
	}
	return nil
}
func observerReadFrame(r io.Reader, marker string) ([]byte, error) {
	var header [12]byte
	if _, err := io.ReadFull(r, header[:]); err != nil || string(header[:8]) != marker {
		return nil, errMigrationUnavailable
	}
	count := binary.BigEndian.Uint32(header[8:])
	if count == 0 || count > migrationObserverLimit {
		return nil, errMigrationUnavailable
	}
	data := make([]byte, count)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, errMigrationUnavailable
	}
	return data, nil
}
func decodeMigrationObserverResponse(data []byte, request migrationObserverRequest, requestData []byte) (migrationRuntimeObservation, error) {
	if request.Mode != "" && request.Mode != preserveExtensionMode && !unifiedRuntimeMode(request.Mode) {
		return migrationRuntimeObservation{}, errMigrationUnavailable
	}
	var response migrationObserverResponse
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&response) != nil || decoder.Decode(new(any)) != io.EOF {
		return migrationRuntimeObservation{}, errMigrationUnavailable
	}
	canonical, _ := json.Marshal(response)
	at := time.UnixMilli(response.ObservedAtUnixMilliseconds)
	if !bytes.Equal(data, canonical) || response.Version != 1 || response.Nonce != request.Nonce || response.Session != request.Session || response.ManifestSHA256 != request.ManifestSHA256 || response.RequestSHA256 != migrationDigest(requestData) || time.Now().UnixMilli() >= request.DeadlineUnixMilliseconds || at.After(time.Now()) || time.Since(at) > 30*time.Second || !validMigrationID(response.SourceReceiptSHA256) || response.Mode != request.Mode || (request.Mode == "" && !validMigrationID(response.StorageSHA256)) || (request.Mode != "" && response.StorageSHA256 != "") || !migrationPackagedPath(response.LoadedExtensionPath) || len(response.StoppedExecutables) == 0 || len(response.StoppedExecutables) > 8 {
		return migrationRuntimeObservation{}, errMigrationUnavailable
	}
	seen := map[string]bool{}
	for _, path := range response.StoppedExecutables {
		if !migrationPackagedPath(path) || seen[path] {
			return migrationRuntimeObservation{}, errMigrationUnavailable
		}
		seen[path] = true
	}
	return migrationRuntimeObservation{mode: response.Mode, at: at, receiptSHA256: migrationDigest(data), loadedExtensionPath: response.LoadedExtensionPath, extensionID: response.ExtensionID, storageSHA256: response.StorageSHA256, stoppedExecutables: response.StoppedExecutables, oldConsoleRequirement: response.OldConsoleRequirement, oldConsoleBirth: response.OldConsoleBirth}, nil
}
func (o *migrationAuthenticatedObserver) observe(ctx context.Context) (migrationRuntimeObservation, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if migrationContext(ctx) != nil || o.count >= 128 {
		return migrationRuntimeObservation{}, errMigrationUnavailable
	}
	o.count++
	authorized, err := o.authority.workerAuthority(ctx)
	if err != nil {
		return migrationRuntimeObservation{}, errMigrationUnavailable
	}
	bounded, cancel := context.WithTimeout(authorized, 5*time.Second)
	defer cancel()
	deadline, _ := bounded.Deadline()
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return migrationRuntimeObservation{}, errMigrationUnavailable
	}
	request := migrationObserverRequest{Mode: o.mode, Version: 1, Nonce: hex.EncodeToString(nonce[:]), Session: o.session, ManifestSHA256: o.manifest, DeadlineUnixMilliseconds: deadline.UnixMilli()}
	payload, _ := json.Marshal(request)
	a := o.authority
	a.mu.Lock()
	if a.closed || !a.initialized || a.peer(a.channel) != nil || a.channel.SetDeadline(deadline) != nil {
		a.mu.Unlock()
		return migrationRuntimeObservation{}, errMigrationUnavailable
	}
	stop := context.AfterFunc(bounded, func() { a.channel.Close() })
	err = observerWriteFrame(a.channel, "MMOBSQ\x00\x01", payload)
	var data []byte
	if err == nil && a.peer(a.channel) == nil {
		data, err = observerReadFrame(a.channel, "MMOBSR\x00\x01")
	} else {
		err = errMigrationUnavailable
	}
	stop()
	if err != nil || bounded.Err() != nil || a.peer(a.channel) != nil {
		a.closeLocked()
		a.mu.Unlock()
		return migrationRuntimeObservation{}, errMigrationUnavailable
	}
	a.mu.Unlock()
	if _, err = a.workerAuthority(authorized); err != nil {
		return migrationRuntimeObservation{}, errMigrationUnavailable
	}
	proof, decodeErr := decodeMigrationObserverResponse(data, request, payload)
	if decodeErr != nil {
		a.close()
	}
	return proof, decodeErr
}
func (o *migrationAuthenticatedObserver) terminal(ctx context.Context) (migrationRuntimeTerminalEvidence, error) {
	if o == nil || o.readiness == nil || migrationContext(ctx) != nil {
		return migrationRuntimeTerminalEvidence{}, errMigrationUnavailable
	}
	if _, err := o.authority.workerAuthority(ctx); err != nil {
		return migrationRuntimeTerminalEvidence{}, errMigrationUnavailable
	}
	return o.readiness(ctx)
}
