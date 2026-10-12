package keychain

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"regexp"
	"sync"

	"github.com/viant/mechanize/auth"
)

const migrationWorkerFrameLimit = 32768
const migrationWorkerMessageLimit = 16

var migrationWorkerExecutorPin = regexp.MustCompile(`^identifier "com\.viant\.mechanize\.custody-migration" and cdhash H"[a-f0-9]{40}"$`)

// Only this closed envelope crosses the private worker channel. Options,
// credentials, caller roles, authorization claims, approval tokens and policy
// handles are never accepted from request JSON.
type migrationWorkerRequest struct {
	Version   int    `json:"version"`
	ID        string `json:"id"`
	Session   string `json:"session"`
	Operation string `json:"op"`
}
type migrationWorkerResponse struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Session string `json:"session"`
	Status  string `json:"status"`
	// Opaque public item metadata, confined to the private prepare reply. Never
	// forward this response type to MCP, general logs or user-facing receipts.
	Identity []byte `json:"identity,omitempty"`
}

func validMigrationWorkerRequest(request migrationWorkerRequest) bool {
	if request.Version != 1 || !validMigrationID(request.ID) || !validMigrationID(request.Session) {
		return false
	}
	switch request.Operation {
	case "prepare", "verify", "commit", "inspect", "close":
		return true
	}
	return false
}
func validMigrationWorkerResponse(response migrationWorkerResponse) bool {
	if response.Version != 1 || !validMigrationID(response.ID) || !validMigrationID(response.Session) {
		return false
	}
	if response.Status == "prepared" {
		return validMasterIdentity(response.Identity)
	}
	if len(response.Identity) != 0 {
		return false
	}
	switch response.Status {
	case "checked", "verified", "unknown", "unavailable", "closed":
		return true
	}
	return false
}
func readMigrationWorkerFrame(reader io.Reader, result any) error {
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return errMigrationUnavailable
	}
	count := binary.BigEndian.Uint32(prefix[:])
	if count == 0 || count > migrationWorkerFrameLimit {
		return errMigrationUnavailable
	}
	data := make([]byte, int(count))
	if _, err := io.ReadFull(reader, data); err != nil {
		return errMigrationUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(result) != nil {
		return errMigrationUnavailable
	}
	canonical, err := json.Marshal(result)
	// Canonical equality rejects duplicates, trailing JSON, unknown/omitted
	// fields and alternate encodings, rather than silently taking a last value.
	if err != nil || !bytes.Equal(data, canonical) {
		return errMigrationUnavailable
	}
	return nil
}
func writeMigrationWorkerFrame(writer io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) == 0 || len(data) > migrationWorkerFrameLimit {
		return errMigrationUnavailable
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(data)))
	frame := append(prefix[:], data...)
	for len(frame) > 0 {
		n, err := writer.Write(frame)
		if err != nil || n <= 0 || n > len(frame) {
			return errMigrationUnavailable
		}
		frame = frame[n:]
	}
	return nil
}
func readMigrationWorkerRequest(reader io.Reader) (migrationWorkerRequest, error) {
	var request migrationWorkerRequest
	if readMigrationWorkerFrame(reader, &request) != nil || !validMigrationWorkerRequest(request) {
		return migrationWorkerRequest{}, errMigrationUnavailable
	}
	return request, nil
}
func writeMigrationWorkerRequest(writer io.Writer, request migrationWorkerRequest) error {
	if !validMigrationWorkerRequest(request) {
		return errMigrationUnavailable
	}
	return writeMigrationWorkerFrame(writer, request)
}
func readMigrationWorkerResponse(reader io.Reader) (migrationWorkerResponse, error) {
	var response migrationWorkerResponse
	if readMigrationWorkerFrame(reader, &response) != nil || !validMigrationWorkerResponse(response) {
		return migrationWorkerResponse{}, errMigrationUnavailable
	}
	return response, nil
}
func writeMigrationWorkerResponse(writer io.Writer, response migrationWorkerResponse) error {
	if !validMigrationWorkerResponse(response) {
		return errMigrationUnavailable
	}
	return writeMigrationWorkerFrame(writer, response)
}

// Config is populated only by trusted installer bootstrap, never wire decoding.
// expectedIdentity is set only for restart reconciliation from the checked
// durable journal. In that mode preparation and mutation are permanently absent.
type migrationWorkerConfig struct {
	options             migrationOptions
	executorRequirement string
	session             string
	expectedIdentity    []byte
}

// authority must authenticate the already-pinned parent/channel independently
// of request bytes. It supplies existing NativeHuman authority; this file never
// calls auth.WithNativeHuman and never derives authority from any wire field.
type migrationWorkerAuthority func(context.Context) (context.Context, error)

type migrationWorkerApprovalBinding struct {
	Session             string
	RequestID           string
	OptionsSHA256       string
	ExecutorRequirement string
	ItemReferenceSHA256 string
}

// Approval is a separate attestation by trusted parent transport. The callback
// must bind actual local-human approval AND the durably written matching unknown
// journal to this exact session/operation/options/item. A nil error is not to be
// manufactured by decoding a caller bool/token or merely enabling platform UI.
// The parent coordinator must sync its unknown journal BEFORE sending commit.
type migrationWorkerApproval func(context.Context, migrationWorkerApprovalBinding) error

type migrationWorkerExecutor interface {
	prepare(context.Context, migrationOptions) (*migrationPrepared, error)
	verifyBeforeCommit(context.Context, migrationOptions, *migrationPrepared) error
	commitAsIsolatedHelper(context.Context, migrationOptions, *migrationPrepared, string) error
	inspect(context.Context, migrationOptions, []byte) (migrationInspection, error)
}

type migrationWorker struct {
	mu                 sync.Mutex
	started            bool
	config             migrationWorkerConfig
	executor           migrationWorkerExecutor
	authority          migrationWorkerAuthority
	approval           migrationWorkerApproval
	phase              string
	prepared           *migrationPrepared
	identity           []byte
	dispatched         bool
	seen               map[string]bool
	authorityPinned    bool
	principalNamespace string
	principalClientID  string
}

// Private only: no executable command, production constructor, authority
// bootstrap or approval transport is exposed. Native execution remains gated by
// its exact own-code role and requires the separately bounded process watchdog.
func newMigrationWorker(config migrationWorkerConfig, executor migrationWorkerExecutor, authority migrationWorkerAuthority, approval migrationWorkerApproval) (*migrationWorker, error) {
	if !validMigrationOptions(config.options) || !migrationWorkerExecutorPin.MatchString(config.executorRequirement) || !validMigrationID(config.session) ||
		executor == nil || authority == nil || approval == nil || (config.expectedIdentity != nil && !validMasterIdentity(config.expectedIdentity)) {
		return nil, errMigrationUnavailable
	}
	config.expectedIdentity = bytes.Clone(config.expectedIdentity)
	worker := &migrationWorker{config: config, executor: executor, authority: authority, approval: approval, phase: "idle", identity: bytes.Clone(config.expectedIdentity), seen: make(map[string]bool)}
	if config.expectedIdentity != nil {
		worker.phase = "unknown"
	}
	return worker, nil
}
func (*migrationWorker) String() string               { return "Keychain migration worker" }
func (*migrationWorker) GoString() string             { return "Keychain migration worker" }
func (*migrationWorker) MarshalJSON() ([]byte, error) { return []byte(`{"state":"private"}`), nil }
func (w *migrationWorker) release() {
	prepared := w.prepared
	w.prepared = nil
	if prepared != nil && prepared.dispose != nil {
		prepared.dispose()
	}
}
func (w *migrationWorker) failureStatus() string {
	if w.dispatched || w.phase == "unknown" {
		w.phase = "unknown"
		return "unknown"
	}
	w.phase = "unavailable"
	return "unavailable"
}
func (w *migrationWorker) authorize(parent context.Context) (context.Context, func(), error) {
	if parent == nil || parent.Err() != nil {
		return nil, nil, errMigrationUnavailable
	}
	parentDeadline, bounded := parent.Deadline()
	if !bounded {
		return nil, nil, errMigrationUnavailable
	}
	authorized, err := w.authority(parent)
	if err != nil || parent.Err() != nil || migrationContext(authorized) != nil {
		return nil, nil, errMigrationUnavailable
	}
	deadline, _ := authorized.Deadline()
	if deadline.After(parentDeadline) {
		return nil, nil, errMigrationUnavailable
	}
	principal, err := auth.FromContext(authorized)
	if err != nil {
		return nil, nil, errMigrationUnavailable
	}
	// One verified operation owner must retain custody of this entire session.
	// Another native administrator or a different client is not continuation
	// authority for a preparation already bound to the original parent.
	if w.authorityPinned {
		if principal.Namespace != w.principalNamespace || principal.ClientID != w.principalClientID {
			return nil, nil, errMigrationUnavailable
		}
	} else {
		w.authorityPinned = true
		w.principalNamespace = principal.Namespace
		w.principalClientID = principal.ClientID
	}
	ctx, cancel := context.WithCancel(authorized)
	stop := context.AfterFunc(parent, cancel)
	return ctx, func() { stop(); cancel() }, nil
}
func (w *migrationWorker) identityMatches() bool {
	return w.prepared != nil && validMasterIdentity(w.identity) && bytes.Equal(w.prepared.identity, w.identity)
}
func (w *migrationWorker) inspect(ctx context.Context) bool {
	if !validMasterIdentity(w.identity) {
		return false
	}
	actual, err := w.executor.inspect(ctx, w.config.options, bytes.Clone(w.identity))
	return err == nil && migrationContext(ctx) == nil && actual.exactNewPolicy && bytes.Equal(actual.identity, w.identity)
}
func (w *migrationWorker) dispatch(ctx context.Context, request migrationWorkerRequest) (migrationWorkerResponse, bool) {
	response := migrationWorkerResponse{Version: 1, ID: request.ID, Session: w.config.session}
	refuse := func() (migrationWorkerResponse, bool) {
		response.Status = w.failureStatus()
		w.release()
		return response, true
	}
	if migrationContext(ctx) != nil || !validMigrationWorkerRequest(request) || request.Session != w.config.session || w.seen[request.ID] || len(w.seen) >= migrationWorkerMessageLimit {
		return refuse()
	}
	w.seen[request.ID] = true
	switch request.Operation {
	case "prepare":
		if w.phase != "idle" || w.config.expectedIdentity != nil {
			return refuse()
		}
		prepared, err := w.executor.prepare(ctx, w.config.options)
		w.prepared = prepared
		if err != nil || prepared == nil || prepared.handle == nil || !validMasterIdentity(prepared.identity) || migrationContext(ctx) != nil {
			return refuse()
		}
		w.identity = bytes.Clone(prepared.identity)
		w.phase = "prepared"
		response.Status = "prepared"
		response.Identity = bytes.Clone(w.identity)
	case "verify":
		if w.phase != "prepared" || !w.identityMatches() {
			return refuse()
		}
		if w.executor.verifyBeforeCommit(ctx, w.config.options, w.prepared) != nil || migrationContext(ctx) != nil || !w.identityMatches() {
			return refuse()
		}
		w.phase = "checked"
		response.Status = "checked"
	case "commit":
		if w.phase != "checked" || w.dispatched || !w.identityMatches() {
			return refuse()
		}
		if w.executor.verifyBeforeCommit(ctx, w.config.options, w.prepared) != nil || migrationContext(ctx) != nil || !w.identityMatches() {
			return refuse()
		}
		binding := migrationWorkerApprovalBinding{Session: w.config.session, RequestID: request.ID, OptionsSHA256: migrationOptionsDigest(w.config.options), ExecutorRequirement: w.config.executorRequirement, ItemReferenceSHA256: migrationDigest(w.identity)}
		if w.approval(ctx, binding) != nil || migrationContext(ctx) != nil || !w.identityMatches() {
			return refuse()
		}
		// This latch precedes the one mutation call. Platform errors, cancellation
		// and loss of the acknowledgement never permit replay or reversal.
		w.phase = "unknown"
		w.dispatched = true
		err := w.executor.commitAsIsolatedHelper(ctx, w.config.options, w.prepared, w.config.executorRequirement)
		w.release()
		if err != nil || migrationContext(ctx) != nil {
			response.Status = "unknown"
			return response, false
		}
		if !w.inspect(ctx) {
			response.Status = "unknown"
			return response, false
		}
		w.phase = "verified"
		response.Status = "verified"
	case "inspect":
		if w.phase != "unknown" && w.phase != "verified" {
			return refuse()
		}
		if !w.inspect(ctx) {
			w.phase = "unknown"
			response.Status = "unknown"
			return response, false
		}
		w.phase = "verified"
		response.Status = "verified"
	case "close":
		if w.phase == "unknown" {
			response.Status = "unknown"
		} else {
			response.Status = "closed"
			w.phase = "closed"
		}
		w.release()
		return response, true
	default:
		return refuse()
	}
	return response, false
}

// The private transport must unblock reads/writes on Close. Cancellation closes
// it, but cannot interrupt arbitrary native C work: the process watchdog must
// terminate an unresponsive worker. Authority is checked BEFORE the first read
// and freshly for every operation. A worker/session can be served only once.
func (w *migrationWorker) serve(parent context.Context, channel io.ReadWriteCloser) error {
	if w == nil || channel == nil {
		return errMigrationUnavailable
	}
	w.mu.Lock()
	if w.started {
		w.mu.Unlock()
		return errMigrationUnavailable
	}
	w.started = true
	w.mu.Unlock()
	defer channel.Close()
	defer w.release()
	sessionContext, releaseSession, err := w.authorize(parent)
	if err != nil {
		return errMigrationUnavailable
	}
	defer releaseSession()
	stop := context.AfterFunc(sessionContext, func() { _ = channel.Close() })
	defer stop()
	for i := 0; i < migrationWorkerMessageLimit; i++ {
		request, err := readMigrationWorkerRequest(channel)
		if err != nil {
			if w.failureStatus() == "unknown" {
				return errMigrationUnknown
			}
			return errMigrationUnavailable
		}
		ctx, cleanup, err := w.authorize(sessionContext)
		if err != nil {
			if w.failureStatus() == "unknown" {
				return errMigrationUnknown
			}
			return errMigrationUnavailable
		}
		stopOperation := context.AfterFunc(ctx, func() { _ = channel.Close() })
		response, done := w.dispatch(ctx, request)
		cancelled := migrationContext(ctx) != nil
		if cancelled {
			response.Identity = nil
			response.Status = w.failureStatus()
			done = true
		}
		writeError := writeMigrationWorkerResponse(channel, response)
		expired := migrationContext(ctx) != nil
		stopOperation()
		cleanup()
		if writeError != nil || expired {
			if w.failureStatus() == "unknown" {
				return errMigrationUnknown
			}
			return errMigrationUnavailable
		}
		if done {
			if response.Status == "unknown" {
				return errMigrationUnknown
			}
			if response.Status == "unavailable" {
				return errMigrationUnavailable
			}
			return nil
		}
	}
	if w.failureStatus() == "unknown" {
		return errMigrationUnknown
	}
	return errMigrationUnavailable
}
