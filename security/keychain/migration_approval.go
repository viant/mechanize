package keychain

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/viant/mechanize/auth"
)

const migrationApprovalFrameLimit = 9216
const migrationApprovalAttested byte = 1
const migrationApprovalDeclined byte = 2

// This channel requests attestation of an existing exact transition approval.
// It does not require another human confirmation. The signed console must match
// its retained authorized operation before replying; possession of this socket,
// receipt of the challenge or successful Scy authentication alone is no approval.
// No caller JSON bool, identity assertion or platform-UI toggle is accepted.
type migrationApprovalTransport struct {
	mu        sync.Mutex
	authority *migrationNativeAuthority
	config    migrationWorkerConfig
	journal   migrationJournal
	used      bool
}

func newMigrationApprovalTransport(a *migrationNativeAuthority, config migrationWorkerConfig, journal migrationJournal) (*migrationApprovalTransport, error) {
	if a == nil || journal == nil || !validMigrationBootstrap(config, migrationOptionsDigest(config.options)) || config.expectedIdentity != nil {
		return nil, errMigrationUnavailable
	}
	a.mu.Lock()
	ready := a.initialized && !a.closed && len(a.credential) > 0
	a.mu.Unlock()
	if !ready {
		return nil, errMigrationUnavailable
	}
	return &migrationApprovalTransport{authority: a, config: config, journal: journal}, nil
}
func (*migrationApprovalTransport) String() string   { return "Keychain migration approval transport" }
func (*migrationApprovalTransport) GoString() string { return "Keychain migration approval transport" }
func (*migrationApprovalTransport) MarshalJSON() ([]byte, error) {
	return []byte(`{"state":"private"}`), nil
}

type migrationApprovalRequest struct {
	nonce      [32]byte
	deadline   int64
	binding    migrationWorkerApprovalBinding
	transition migrationTransition
}

func (*migrationApprovalRequest) String() string   { return "Keychain migration approval request" }
func (*migrationApprovalRequest) GoString() string { return "Keychain migration approval request" }
func (*migrationApprovalRequest) MarshalJSON() ([]byte, error) {
	return []byte(`{"state":"private"}`), nil
}
func migrationApprovalFields(r migrationApprovalRequest) []string {
	b, t := r.binding, r.transition
	fields := []string{b.Session, b.RequestID, b.OptionsSHA256, b.ExecutorRequirement, b.ItemReferenceSHA256, t.ID, t.CanonicalExecutable, t.OldRequirement, t.NewRequirement, t.Alias, t.Service, t.Account, t.ItemReferenceSHA256, t.Binding}
	if t.NewCanonicalExecutable != "" {
		fields = append(fields, t.NewCanonicalExecutable, "mechanize-custody-relocation-v2")
	}
	return fields
}
func validMigrationApprovalRequest(r migrationApprovalRequest) bool {
	b, t := r.binding, r.transition
	for _, field := range migrationApprovalFields(r) {
		if !utf8.ValidString(field) {
			return false
		}
	}
	options := migrationOptions{canonicalExecutable: t.CanonicalExecutable, newCanonicalExecutable: t.NewCanonicalExecutable, oldRequirement: t.OldRequirement, newRequirement: t.NewRequirement, alias: t.Alias, item: Item{Service: t.Service, Account: t.Account}}
	unsigned := t
	unsigned.Binding = ""
	// transition() hashes the public transition struct before its
	// Binding is assigned; reuse that exact implementation for the expected value.
	return r.nonce != [32]byte{} && r.deadline > time.Now().UnixNano() && r.deadline <= time.Now().Add(240*time.Second).UnixNano() && validMigrationOptions(options) && validMigrationID(t.ID) && validMigrationID(b.Session) && validMigrationID(b.RequestID) &&
		validMigrationID(b.ItemReferenceSHA256) && t.ItemReferenceSHA256 == b.ItemReferenceSHA256 && b.OptionsSHA256 == migrationOptionsDigest(options) && migrationWorkerExecutorPin.MatchString(b.ExecutorRequirement) && migrationApprovalTransitionDigest(unsigned) == t.Binding
}
func migrationApprovalTransitionDigest(t migrationTransition) string {
	// Same struct encoding as migrationCoordinator.transition; this is public
	// metadata hashing, never a JSON transport or authorization claim.
	data, _ := json.Marshal(t)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func migrationApprovalPayload(r migrationApprovalRequest) ([]byte, error) {
	if !validMigrationApprovalRequest(r) {
		return nil, errMigrationUnavailable
	}
	var buffer bytes.Buffer
	buffer.Write(r.nonce[:])
	binary.Write(&buffer, binary.BigEndian, r.deadline)
	for _, field := range migrationApprovalFields(r) {
		if len(field) > 4096 {
			return nil, errMigrationUnavailable
		}
		binary.Write(&buffer, binary.BigEndian, uint16(len(field)))
		buffer.WriteString(field)
	}
	if buffer.Len() > migrationApprovalFrameLimit {
		return nil, errMigrationUnavailable
	}
	return buffer.Bytes(), nil
}
func writeMigrationApprovalRequest(w io.Writer, r migrationApprovalRequest) ([32]byte, error) {
	var zero [32]byte
	if w == nil {
		return zero, errMigrationUnavailable
	}
	payload, err := migrationApprovalPayload(r)
	if err != nil {
		return zero, err
	}
	header := [12]byte{'M', 'M', 'A', 'P', 'R', 'V', 0, 1}
	binary.BigEndian.PutUint32(header[8:], uint32(len(payload)))
	if migrationWriteAll(w, header[:]) != nil || migrationWriteAll(w, payload) != nil {
		return zero, errMigrationUnavailable
	}
	return sha256.Sum256(payload), nil
}

// Native-console decoder; callers must verify the helper peer before reading and
// must use their retained exact authorization record before emitting attestation.
func readMigrationApprovalRequest(reader io.Reader) (migrationApprovalRequest, [32]byte, error) {
	var result migrationApprovalRequest
	var zero [32]byte
	var header [12]byte
	if reader == nil {
		return result, zero, errMigrationUnavailable
	}
	if _, err := io.ReadFull(reader, header[:]); err != nil || string(header[:8]) != "MMAPRV\x00\x01" {
		return result, zero, errMigrationUnavailable
	}
	count := binary.BigEndian.Uint32(header[8:])
	if count < 40 || count > migrationApprovalFrameLimit {
		return result, zero, errMigrationUnavailable
	}
	payload := make([]byte, count)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return result, zero, errMigrationUnavailable
	}
	input := bytes.NewReader(payload)
	io.ReadFull(input, result.nonce[:])
	binary.Read(input, binary.BigEndian, &result.deadline)
	fields := make([]string, 14)
	for n := range fields {
		var size uint16
		if binary.Read(input, binary.BigEndian, &size) != nil || int(size) > 4096 || int(size) > input.Len() {
			return migrationApprovalRequest{}, zero, errMigrationUnavailable
		}
		value := make([]byte, size)
		io.ReadFull(input, value)
		fields[n] = string(value)
	}
	if input.Len() != 0 {
		extra := make([]string, 2)
		for n := range extra {
			var size uint16
			if binary.Read(input, binary.BigEndian, &size) != nil || size == 0 || size > 4096 || int(size) > input.Len() {
				return migrationApprovalRequest{}, zero, errMigrationUnavailable
			}
			value := make([]byte, size)
			io.ReadFull(input, value)
			extra[n] = string(value)
		}
		if extra[1] != "mechanize-custody-relocation-v2" {
			return migrationApprovalRequest{}, zero, errMigrationUnavailable
		}
		result.transition.NewCanonicalExecutable = extra[0]
	}
	if input.Len() != 0 {
		return migrationApprovalRequest{}, zero, errMigrationUnavailable
	}
	result.binding = migrationWorkerApprovalBinding{Session: fields[0], RequestID: fields[1], OptionsSHA256: fields[2], ExecutorRequirement: fields[3], ItemReferenceSHA256: fields[4]}
	result.transition = migrationTransition{NewCanonicalExecutable: result.transition.NewCanonicalExecutable, ID: fields[5], CanonicalExecutable: fields[6], OldRequirement: fields[7], NewRequirement: fields[8], Alias: fields[9], Service: fields[10], Account: fields[11], ItemReferenceSHA256: fields[12], Binding: fields[13]}
	if !validMigrationApprovalRequest(result) {
		return migrationApprovalRequest{}, zero, errMigrationUnavailable
	}
	return result, sha256.Sum256(payload), nil
}

// Fixed-width native attestation: marker + disposition + challenge + transcript.
// This is not a bearer grant: it is consumed once on the same verified socket.
func writeMigrationApprovalResponse(writer io.Writer, decision byte, nonce, digest [32]byte) error {
	if writer == nil {
		return errMigrationUnavailable
	}
	if decision != migrationApprovalAttested && decision != migrationApprovalDeclined {
		return errMigrationUnavailable
	}
	frame := [73]byte{'M', 'M', 'A', 'C', 'K', 0, 0, 1}
	frame[8] = decision
	copy(frame[9:41], nonce[:])
	copy(frame[41:], digest[:])
	return migrationWriteAll(writer, frame[:])
}
func readMigrationApprovalResponse(reader io.Reader, nonce, digest [32]byte) error {
	var frame [73]byte
	if reader == nil {
		return errMigrationUnavailable
	}
	if _, err := io.ReadFull(reader, frame[:]); err != nil || string(frame[:8]) != "MMACK\x00\x00\x01" || frame[8] != migrationApprovalAttested || !bytes.Equal(frame[9:41], nonce[:]) || !bytes.Equal(frame[41:], digest[:]) {
		return errMigrationUnavailable
	}
	return nil
}
func (p *migrationApprovalTransport) record(ctx context.Context, b migrationWorkerApprovalBinding) (*migrationJournalRecord, error) {
	r, err := p.journal.load(ctx)
	if err != nil || r == nil || r.state != migrationUnknown || !validMigrationID(r.transitionID) || r.optionsSHA256 != b.OptionsSHA256 || !validMasterIdentity(r.identity) || migrationDigest(r.identity) != b.ItemReferenceSHA256 {
		return nil, errMigrationUnavailable
	}
	copy := *r
	copy.identity = bytes.Clone(r.identity)
	return &copy, nil
}
func (p *migrationApprovalTransport) approve(ctx context.Context, b migrationWorkerApprovalBinding) error {
	if p == nil || migrationContext(ctx) != nil {
		return errMigrationUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used {
		return errMigrationUnavailable
	}
	p.used = true
	if b.Session != p.config.session || b.OptionsSHA256 != migrationOptionsDigest(p.config.options) || b.ExecutorRequirement != p.config.executorRequirement || !validMigrationID(b.RequestID) || !validMigrationID(b.ItemReferenceSHA256) {
		return errMigrationUnavailable
	}
	owner, err := auth.FromContext(ctx)
	if err != nil || owner.Namespace != p.authority.enrollment.namespace || owner.ClientID != p.authority.enrollment.clientID {
		return errMigrationUnavailable
	}
	authorized, err := p.authority.workerAuthority(ctx)
	if err != nil {
		return errMigrationUnavailable
	}
	before, err := p.record(authorized, b)
	if err != nil {
		return errMigrationUnavailable
	}
	deadline, _ := authorized.Deadline()
	coordinator := migrationCoordinator{options: p.config.options, record: before}
	request := migrationApprovalRequest{binding: b, transition: coordinator.transition(), deadline: deadline.UnixNano()}
	if _, err = rand.Read(request.nonce[:]); err != nil {
		return errMigrationUnavailable
	}
	// Serialize with authority revalidation on this same connection. Initialization
	// already consumed the credential frame; no other decoder may read concurrently.
	a := p.authority
	a.mu.Lock()
	if a.closed || !a.initialized || a.peer(a.channel) != nil {
		a.mu.Unlock()
		return errMigrationUnavailable
	}
	if a.channel.SetDeadline(deadline) != nil {
		a.closeLocked()
		a.mu.Unlock()
		return errMigrationUnavailable
	}
	stop := context.AfterFunc(authorized, func() { _ = a.channel.Close() })
	digest, writeErr := writeMigrationApprovalRequest(a.channel, request)
	var readErr error
	if writeErr == nil {
		readErr = readMigrationApprovalResponse(a.channel, request.nonce, digest)
	}
	stop()
	if writeErr != nil || readErr != nil || authorized.Err() != nil || a.peer(a.channel) != nil {
		a.closeLocked()
		a.mu.Unlock()
		return errMigrationUnavailable
	}
	a.mu.Unlock()
	verified, err := a.workerAuthority(authorized)
	if err != nil {
		return errMigrationUnavailable
	}
	after, err := p.record(verified, b)
	if err != nil || after.transitionID != before.transitionID || !bytes.Equal(after.identity, before.identity) || after.optionsSHA256 != before.optionsSHA256 || migrationContext(verified) != nil || time.Now().UnixNano() >= request.deadline {
		return errMigrationUnavailable
	}
	return nil
}
