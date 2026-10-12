package keychain

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/viant/mechanize/auth"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type approvalJournalFixture struct {
	mu    sync.Mutex
	value migrationJournalRecord
	loads int
}

func (j *approvalJournalFixture) load(context.Context) (*migrationJournalRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.loads++
	r := j.value
	r.identity = bytes.Clone(r.identity)
	return &r, nil
}
func (*approvalJournalFixture) markUnknown(context.Context, migrationJournalRecord) error {
	return errMigrationUnavailable
}
func (*approvalJournalFixture) markVerified(context.Context, migrationJournalRecord) error {
	return errMigrationUnavailable
}
func (j *approvalJournalFixture) change(f func(*migrationJournalRecord)) {
	j.mu.Lock()
	defer j.mu.Unlock()
	f(&j.value)
}
func approvalFixture(t *testing.T) (*migrationApprovalTransport, migrationWorkerApprovalBinding, *approvalJournalFixture, *net.UnixConn, context.Context) {
	t.Helper()
	a, _, c, ctx := migrationAuthorityFixture(t)
	sendMigrationCredential(t, c)
	ctx, err := a.workerAuthority(ctx)
	if err != nil {
		t.Fatal(err)
	}
	config := migrationWorkerConfig{options: migrationFixtureOptions(), session: strings.Repeat("a", 64), executorRequirement: `identifier "com.viant.mechanize.custody-migration" and cdhash H"` + strings.Repeat("b", 40) + `"`}
	identity := []byte("synthetic-public-item-reference")
	journal := &approvalJournalFixture{value: migrationJournalRecord{state: migrationUnknown, transitionID: strings.Repeat("c", 64), optionsSHA256: migrationOptionsDigest(config.options), identity: identity}}
	p, err := newMigrationApprovalTransport(a, config, journal)
	if err != nil {
		t.Fatal(err)
	}
	b := migrationWorkerApprovalBinding{Session: config.session, RequestID: strings.Repeat("d", 64), OptionsSHA256: migrationOptionsDigest(config.options), ExecutorRequirement: config.executorRequirement, ItemReferenceSHA256: migrationDigest(identity)}
	return p, b, journal, c, ctx
}
func runApprovalConsole(c *net.UnixConn, respond func(migrationApprovalRequest, [32]byte) error) <-chan error {
	done := make(chan error, 1)
	go func() {
		r, d, e := readMigrationApprovalRequest(c)
		if e == nil {
			e = respond(r, d)
		}
		done <- e
	}()
	return done
}
func TestMigrationApprovalExactExistingAuthorizationAttestation(t *testing.T) {
	p, b, j, c, ctx := approvalFixture(t)
	done := runApprovalConsole(c, func(r migrationApprovalRequest, d [32]byte) error {
		if r.binding != b || r.transition.ID != j.value.transitionID || r.transition.CanonicalExecutable != p.config.options.canonicalExecutable {
			return errors.New("challenge binding mismatch")
		}
		return writeMigrationApprovalResponse(c, migrationApprovalAttested, r.nonce, d)
	})
	if err := p.approve(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if j.loads != 2 {
		t.Fatal("durable unknown record was not rechecked")
	}
	if p.approve(ctx, b) == nil {
		t.Fatal("approval challenge replayed")
	}
	for _, value := range []any{p, &migrationApprovalRequest{binding: b}} {
		out := fmt.Sprintf("%v %#v", value, value)
		encoded, _ := json.Marshal(value)
		out += string(encoded)
		if strings.Contains(out, b.Session) || strings.Contains(out, "synthetic-private") {
			t.Fatal("private approval details exposed")
		}
	}
}
func TestMigrationApprovalRejectsChangedWorkerBindingBeforeWire(t *testing.T) {
	for _, field := range []string{"session", "request", "options", "helper", "item"} {
		t.Run(field, func(t *testing.T) {
			p, b, j, _, ctx := approvalFixture(t)
			switch field {
			case "session":
				b.Session = strings.Repeat("1", 64)
			case "request":
				b.RequestID = "caller-id"
			case "options":
				b.OptionsSHA256 = strings.Repeat("2", 64)
			case "helper":
				b.ExecutorRequirement = strings.Replace(b.ExecutorRequirement, "custody-migration", "broker", 1)
			case "item":
				b.ItemReferenceSHA256 = strings.Repeat("3", 64)
			}
			if p.approve(ctx, b) != errMigrationUnavailable {
				t.Fatal("changed binding admitted")
			}
			if j.loads > 1 {
				t.Fatal("invalid request reached response phase")
			}
		})
	}
}
func TestMigrationApprovalRequiresUnknownMatchingJournal(t *testing.T) {
	for _, field := range []string{"state", "options", "identity", "transition"} {
		t.Run(field, func(t *testing.T) {
			p, b, j, _, ctx := approvalFixture(t)
			j.change(func(r *migrationJournalRecord) {
				switch field {
				case "state":
					r.state = migrationVerified
				case "options":
					r.optionsSHA256 = strings.Repeat("1", 64)
				case "identity":
					r.identity = []byte("another-item")
				case "transition":
					r.transitionID = "invalid"
				}
			})
			if p.approve(ctx, b) != errMigrationUnavailable {
				t.Fatal("missing durable unknown binding admitted")
			}
		})
	}
}
func TestMigrationApprovalRejectsMalformedDeniedOrReplayedAttestation(t *testing.T) {
	for _, mode := range []string{"decline", "nonce", "transcript", "json", "eof"} {
		t.Run(mode, func(t *testing.T) {
			p, b, _, c, ctx := approvalFixture(t)
			done := runApprovalConsole(c, func(r migrationApprovalRequest, d [32]byte) error {
				decision := migrationApprovalAttested
				switch mode {
				case "decline":
					decision = migrationApprovalDeclined
				case "nonce":
					r.nonce[0] ^= 1
				case "transcript":
					d[0] ^= 1
				case "json":
					_, err := c.Write([]byte(`{"approved":true,"nativeHuman":true}` + strings.Repeat(" ", 73)))
					return err
				case "eof":
					return c.Close()
				}
				return writeMigrationApprovalResponse(c, decision, r.nonce, d)
			})
			if p.approve(ctx, b) != errMigrationUnavailable {
				t.Fatal("unbound native response admitted")
			}
			<-done
		})
	}
}
func TestMigrationApprovalRechecksJournalAndAuthorityAfterResponse(t *testing.T) {
	for _, mode := range []string{"journal-state", "journal-transition", "journal-item", "admin-revoked", "peer-revoked"} {
		t.Run(mode, func(t *testing.T) {
			p, b, j, c, ctx := approvalFixture(t)
			done := runApprovalConsole(c, func(r migrationApprovalRequest, d [32]byte) error {
				switch mode {
				case "journal-state":
					j.change(func(v *migrationJournalRecord) { v.state = migrationVerified })
				case "journal-transition":
					j.change(func(v *migrationJournalRecord) { v.transitionID = strings.Repeat("e", 64) })
				case "journal-item":
					j.change(func(v *migrationJournalRecord) { v.identity = []byte("changed-item") })
				}
				return writeMigrationApprovalResponse(c, migrationApprovalAttested, r.nonce, d)
			})
			// Invalidate deterministically on post-response verification without a race
			// between the console fixture and the authority's fields.
			if mode == "admin-revoked" {
				p.authority.verifier = &approvalRevokingVerifier{base: p.authority.verifier, remaining: 1}
			}
			if mode == "peer-revoked" {
				original := p.authority.peer
				calls := 0
				p.authority.peer = func(conn *net.UnixConn) error {
					calls++
					if calls >= 5 {
						return errMigrationUnavailable
					}
					return original(conn)
				}
			}
			if p.approve(ctx, b) != errMigrationUnavailable {
				t.Fatal("stale response admitted")
			}
			<-done
		})
	}
}

type approvalRevokingVerifier struct {
	base      migrationCredentialVerifier
	remaining int
}

func (v *approvalRevokingVerifier) Verify(ctx context.Context, s string) (auth.Principal, error) {
	if v.remaining == 0 {
		return auth.Principal{}, errMigrationUnavailable
	}
	v.remaining--
	return v.base.Verify(ctx, s)
}

func TestMigrationApprovalCancellationClosesBlockedAttestation(t *testing.T) {
	p, b, _, c, ctx := approvalFixture(t)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := runApprovalConsole(c, func(migrationApprovalRequest, [32]byte) error { cancel(); return nil })
	start := time.Now()
	if p.approve(ctx, b) != errMigrationUnavailable {
		t.Fatal("cancelled attestation admitted")
	}
	<-done
	if time.Since(start) > time.Second {
		t.Fatal("approval read ignored cancellation")
	}
}
func TestMigrationApprovalCodecRejectsOversizeTrailingAndAlteredFields(t *testing.T) {
	p, b, j, _, _ := approvalFixture(t)
	coordinator := migrationCoordinator{options: p.config.options, record: &j.value}
	request := migrationApprovalRequest{binding: b, transition: coordinator.transition(), deadline: time.Now().Add(time.Second).UnixNano()}
	request.nonce[0] = 1
	var wire bytes.Buffer
	if _, err := writeMigrationApprovalRequest(&wire, request); err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(wire.Bytes())
	for _, mode := range []string{"oversize", "trailing", "magic", "truncated", "field"} {
		t.Run(mode, func(t *testing.T) {
			data := bytes.Clone(original)
			switch mode {
			case "oversize":
				binary.BigEndian.PutUint32(data[8:12], migrationApprovalFrameLimit+1)
			case "trailing":
				data = append(data, 0)
				binary.BigEndian.PutUint32(data[8:12], uint32(len(data)-12))
			case "magic":
				data[0] = 'X'
			case "truncated":
				data = data[:len(data)-1]
			case "field":
				data[len(data)-1] ^= 1
			}
			if _, _, err := readMigrationApprovalRequest(bytes.NewReader(data)); err == nil {
				t.Fatal("malformed challenge admitted")
			}
		})
	}
}

func TestMigrationApprovalWorkerCommitUsesBoundTransport(t *testing.T) {
	for _, decision := range []byte{migrationApprovalAttested, migrationApprovalDeclined} {
		t.Run(fmt.Sprint(decision), func(t *testing.T) {
			p, _, j, c, ctx := approvalFixture(t)
			events := &[]string{}
			backend := &migrationWorkerExecutorFixture{migrationBackendFixture: &migrationBackendFixture{events: events, newPolicy: true}}
			worker, err := newMigrationWorker(p.config, backend, p.authority.workerAuthority, p.approve)
			if err != nil {
				t.Fatal(err)
			}
			if reply, _ := worker.dispatch(ctx, migrationWorkerReq(worker, 1, "prepare")); reply.Status != "prepared" {
				t.Fatal("fixture prepare failed")
			}
			if reply, _ := worker.dispatch(ctx, migrationWorkerReq(worker, 2, "verify")); reply.Status != "checked" {
				t.Fatal("fixture verify failed")
			}
			j.change(func(r *migrationJournalRecord) { r.identity = bytes.Clone(worker.identity) })
			done := runApprovalConsole(c, func(r migrationApprovalRequest, d [32]byte) error {
				if r.binding.RequestID != fmt.Sprintf("%064x", 3) || r.binding.ItemReferenceSHA256 != migrationDigest(worker.identity) {
					return errors.New("worker binding not attested")
				}
				return writeMigrationApprovalResponse(c, decision, r.nonce, d)
			})
			reply, _ := worker.dispatch(ctx, migrationWorkerReq(worker, 3, "commit"))
			<-done
			if decision == migrationApprovalAttested {
				if reply.Status != "verified" || backend.commits != 1 {
					t.Fatal("bound attestation did not permit one fixture commit")
				}
			} else if backend.commits != 0 || reply.Status != "unavailable" {
				t.Fatal("declined attestation dispatched ACL")
			}
		})
	}
}
func TestMigrationApprovalExpiredChallengeIsNotAnAuthorization(t *testing.T) {
	p, b, j, _, _ := approvalFixture(t)
	coordinator := migrationCoordinator{options: p.config.options, record: &j.value}
	r := migrationApprovalRequest{binding: b, transition: coordinator.transition(), deadline: time.Now().Add(-time.Second).UnixNano()}
	r.nonce[0] = 1
	if _, err := migrationApprovalPayload(r); err != errMigrationUnavailable {
		t.Fatal("expired challenge accepted")
	}
	r.deadline = time.Now().Add(time.Hour).UnixNano()
	if _, err := migrationApprovalPayload(r); err != errMigrationUnavailable {
		t.Fatal("unbounded challenge accepted")
	}
}
