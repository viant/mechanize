package keychain

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/viant/mechanize/auth"
)

// This coordinator has no exported constructor, RPC or upgrade bypass. Its
// dependencies belong to the qualified local installer, never untrusted
// UI/transport arguments. Native adapters and staging are composed separately.
var errMigrationUnavailable = errors.New("Keychain custody migration unavailable")
var errMigrationUnknown = errors.New("Keychain custody migration outcome unknown")

var migrationRequirement = regexp.MustCompile(`^identifier "com\.viant\.mechanize\.broker" and cdhash H"[a-f0-9]{40}"$`)

type migrationOptions struct {
	canonicalExecutable    string
	newCanonicalExecutable string
	oldRequirement         string
	newRequirement         string
	alias                  string
	item                   Item
}

type migrationState string

const (
	migrationIdle          migrationState = "idle"
	migrationPreparedState migrationState = "prepared"
	migrationBlocked       migrationState = "unavailable"
	migrationUnknown       migrationState = "unknown"
	migrationVerified      migrationState = "verified"
)

// Receipts contain no item identity, policy, credentials or backend errors.
// Verified means metadata equality only, never a key-read or decryption test.
type migrationReceipt struct {
	State        migrationState `json:"state"`
	TransitionID string         `json:"transitionId,omitempty"`
}

// Local approval is independent of enabling platform UI. A trusted local UI
// must show and approve this exact immutable transition and return its binding.
// No approval is inferred from NativeHuman, a deadline or successful platform UI.
type migrationTransition struct {
	ID                     string
	CanonicalExecutable    string
	OldRequirement         string
	NewRequirement         string
	Alias                  string
	Service                string
	Account                string
	ItemReferenceSHA256    string
	Binding                string
	NewCanonicalExecutable string `json:",omitempty"`
}
type migrationApproval struct {
	approved bool
	binding  string
}
type migrationLocalApproval func(context.Context, migrationTransition) (migrationApproval, error)

type migrationPrepared struct {
	identity []byte
	handle   any
	dispose  func()
}

func (*migrationPrepared) String() string               { return "Keychain migration preparation" }
func (*migrationPrepared) GoString() string             { return "Keychain migration preparation" }
func (*migrationPrepared) MarshalJSON() ([]byte, error) { return []byte(`{"state":"private"}`), nil }

type migrationInspection struct {
	identity       []byte
	exactNewPolicy bool
}

// All methods are metadata-only and must honor ctx. prepare captures the exact
// old full policy/item while old canonical bytes still exist. verifyBeforeCommit
// checks the new canonical code pin and exact old policy/same item. commit MUST
// independently repeat those checks immediately before exactly one existing ACL
// entry replacement; it must never add/delete items, read key data, rewrite owner,
// introduce dual trust, retry, or undo. inspect freshly verifies canonical new
// code and the complete exact new policy, not a cached prepared access object.
// A blocking native authorization call requires a separately bounded native
// execution design; this portable coordinator cannot cancel an arbitrary C call.
type migrationBackend interface {
	prepare(context.Context, migrationOptions) (*migrationPrepared, error)
	verifyBeforeCommit(context.Context, migrationOptions, *migrationPrepared) error
	commit(context.Context, migrationOptions, *migrationPrepared) error
	inspect(context.Context, migrationOptions, []byte) (migrationInspection, error)
}

// A qualified durable implementation must atomically persist/sync markUnknown
// BEFORE commit can dispatch, refuse malformed/foreign records, and serialize
// processes. markVerified compares the complete matching prior unknown record;
// it retains a terminal receipt, never deletes the write-ahead barrier. A write
// error may already have committed and must always be treated as uncertain.
// The private file journal supplies this persistence contract; callers still
// require independently verified installation and authorization enrollment.
type migrationJournal interface {
	load(context.Context) (*migrationJournalRecord, error)
	markUnknown(context.Context, migrationJournalRecord) error
	markVerified(context.Context, migrationJournalRecord) error
}

type migrationJournalRecord struct {
	state         migrationState
	transitionID  string
	optionsSHA256 string
	identity      []byte
}

func (migrationJournalRecord) String() string   { return "Keychain migration journal" }
func (migrationJournalRecord) GoString() string { return "Keychain migration journal" }
func (migrationJournalRecord) MarshalJSON() ([]byte, error) {
	return []byte(`{"state":"private"}`), nil
}

type migrationCoordinator struct {
	adoption *migrationPreparationAdoption
	mu       sync.Mutex
	options  migrationOptions
	backend  migrationBackend
	journal  migrationJournal
	approve  migrationLocalApproval
	state    migrationState
	prepared *migrationPrepared
	record   *migrationJournalRecord
}

// The backend, journal and approval callback are trusted, private dependencies.
// Syntactic validation is not enrollment authorization: the eventual installer
// must construct these options from frozen, independently verified enrollment.
func newMigrationCoordinator(options migrationOptions, backend migrationBackend, journal migrationJournal, approve migrationLocalApproval) (*migrationCoordinator, error) {
	if backend == nil || journal == nil || approve == nil || !validMigrationOptions(options) {
		return nil, errMigrationUnavailable
	}
	return &migrationCoordinator{options: options, backend: backend, journal: journal, approve: approve, state: migrationIdle}, nil
}

func validMigrationOptions(o migrationOptions) bool {
	_, referenceErr := Reference(o.alias)
	return referenceErr == nil && validMigrationRelocation(o) && filepath.IsAbs(o.canonicalExecutable) && filepath.Clean(o.canonicalExecutable) == o.canonicalExecutable &&
		o.canonicalExecutable != string(filepath.Separator) && len(o.canonicalExecutable) <= 4096 && !strings.ContainsAny(o.canonicalExecutable, "\x00\r\n") &&
		migrationRequirement.MatchString(o.oldRequirement) && migrationRequirement.MatchString(o.newRequirement) && o.oldRequirement != o.newRequirement &&
		o.item.Service == "com.viant.mechanize.vault" && len(o.item.Account) > 0 && len(o.item.Account) <= 1024 &&
		strings.TrimSpace(o.item.Account) == o.item.Account && !strings.ContainsAny(o.item.Account, "\x00\r\n")
}

func migrationContext(ctx context.Context) error {
	if ctx == nil || !auth.NativeHuman(ctx) {
		return auth.ErrUnauthorized
	}
	if _, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil {
		return errMigrationUnavailable
	}
	return nil
}
func migrationOptionsDigest(o migrationOptions) string {
	// Fixed positional encoding is unambiguous and never contains key data.
	fields := []string{o.canonicalExecutable, o.oldRequirement, o.newRequirement, o.alias, o.item.Service, o.item.Account}
	if o.newCanonicalExecutable != "" {
		fields = append(fields, o.newCanonicalExecutable, "mechanize-custody-relocation-v2")
	}
	data, _ := json.Marshal(fields)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
func migrationDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
func validMigrationID(id string) bool {
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == id
}
func (c *migrationCoordinator) receipt() migrationReceipt {
	result := migrationReceipt{State: c.state}
	if c.record != nil {
		result.TransitionID = c.record.transitionID
	}
	return result
}
func (c *migrationCoordinator) release() {
	if c.prepared != nil {
		if c.prepared.dispose != nil {
			c.prepared.dispose()
		}
		c.prepared = nil
	}
}
func (c *migrationCoordinator) unavailable() (migrationReceipt, error) {
	c.state = migrationBlocked
	c.release()
	return c.receipt(), errMigrationUnavailable
}
func (c *migrationCoordinator) unknown() (migrationReceipt, error) {
	c.state = migrationUnknown
	c.release()
	return c.receipt(), errMigrationUnknown
}
func (c *migrationCoordinator) load(ctx context.Context) error {
	record, err := c.journal.load(ctx)
	if err != nil || ctx.Err() != nil {
		return errMigrationUnavailable
	}
	if record == nil {
		return nil
	}
	if (record.state != migrationUnknown && record.state != migrationVerified) || !validMigrationID(record.transitionID) ||
		record.optionsSHA256 != migrationOptionsDigest(c.options) || !validMasterIdentity(record.identity) {
		return errMigrationUnavailable
	}
	copy := *record
	copy.identity = bytes.Clone(record.identity)
	c.record = &copy
	c.state = copy.state
	return nil
}

// prepare is separate from commit: a qualified installer must place the pinned
// candidate at the final canonical path between these calls. No file moves are
// implemented here; a preparation is tied to one coordinator and one item.
// The installer needs a separate durable staging journal BEFORE replacing files;
// this coordinator's write-ahead record covers the subsequent ACL dispatch only.
func (c *migrationCoordinator) prepare(ctx context.Context) (migrationReceipt, error) {
	if err := migrationContext(ctx); err != nil {
		return migrationReceipt{State: migrationBlocked}, err
	}
	if c == nil {
		return migrationReceipt{State: migrationBlocked}, errMigrationUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := migrationContext(ctx); err != nil {
		return c.receipt(), err
	}
	if c.state != migrationIdle {
		return c.receipt(), errMigrationUnavailable
	}
	if err := c.load(ctx); err != nil {
		return c.unavailable()
	}
	if c.state == migrationUnknown {
		return c.receipt(), errMigrationUnknown
	}
	if c.state == migrationVerified {
		return c.receipt(), errMigrationUnavailable
	}
	if c.adoption != nil && c.adoption.check(ctx, c, true) != nil {
		return c.unavailable()
	}
	prepared, err := c.backend.prepare(ctx, c.options)
	c.prepared = prepared
	if err != nil || prepared == nil || prepared.handle == nil || !validMasterIdentity(prepared.identity) || migrationContext(ctx) != nil {
		return c.unavailable()
	}
	identity := bytes.Clone(prepared.identity)
	var transitionID string
	if c.adoption != nil {
		var err error
		transitionID, err = c.adoption.take(ctx, c, identity)
		if err != nil {
			return c.unavailable()
		}
	} else {
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return c.unavailable()
		}
		transitionID = hex.EncodeToString(nonce[:])
	}
	c.record = &migrationJournalRecord{state: migrationUnknown, transitionID: transitionID, optionsSHA256: migrationOptionsDigest(c.options), identity: identity}
	c.state = migrationPreparedState
	return c.receipt(), nil
}
func (c *migrationCoordinator) transition() migrationTransition {
	t := migrationTransition{ID: c.record.transitionID, CanonicalExecutable: c.options.canonicalExecutable, NewCanonicalExecutable: c.options.newCanonicalExecutable,
		OldRequirement: c.options.oldRequirement, NewRequirement: c.options.newRequirement, Alias: c.options.alias,
		Service: c.options.item.Service, Account: c.options.item.Account, ItemReferenceSHA256: migrationDigest(c.record.identity)}
	data, _ := json.Marshal(t)
	t.Binding = migrationDigest(data)
	return t
}
func (c *migrationCoordinator) preparedIdentityMatches() bool {
	return c.prepared != nil && c.record != nil && bytes.Equal(c.prepared.identity, c.record.identity)
}
func (c *migrationCoordinator) commit(ctx context.Context) (migrationReceipt, error) {
	if err := migrationContext(ctx); err != nil {
		return migrationReceipt{State: migrationBlocked}, err
	}
	if c == nil {
		return migrationReceipt{State: migrationBlocked}, errMigrationUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := migrationContext(ctx); err != nil {
		return c.receipt(), err
	}
	if c.state != migrationPreparedState {
		return c.receipt(), errMigrationUnavailable
	}
	if !c.preparedIdentityMatches() {
		return c.unavailable()
	}
	if c.adoption != nil && c.adoption.check(ctx, c, false) != nil {
		return c.unavailable()
	}
	if err := c.backend.verifyBeforeCommit(ctx, c.options, c.prepared); err != nil || migrationContext(ctx) != nil || !c.preparedIdentityMatches() {
		return c.unavailable()
	}
	transition := c.transition()
	approval, err := c.approve(ctx, transition)
	if err != nil || !approval.approved || approval.binding != transition.Binding || migrationContext(ctx) != nil || !c.preparedIdentityMatches() {
		return c.unavailable()
	}
	// The journal owns durable process exclusion and exact record CAS. Its error
	// may mean an uncertain write; no commit is dispatched and no retry follows.
	c.state = migrationUnknown
	if err := c.journal.markUnknown(ctx, c.recordCopy()); err != nil || migrationContext(ctx) != nil {
		return c.unknown()
	}
	if !c.preparedIdentityMatches() {
		return c.unknown()
	}
	// From this point every error, including cancellation, is unknown. A backend
	// error is never evidence that the platform left the item unchanged.
	if err := c.backend.commit(ctx, c.options, c.prepared); err != nil || migrationContext(ctx) != nil {
		return c.unknown()
	}
	c.release()
	return c.verify(ctx)
}
func (c *migrationCoordinator) recordCopy() migrationJournalRecord {
	copy := *c.record
	copy.identity = bytes.Clone(copy.identity)
	return copy
}
func (c *migrationCoordinator) verify(ctx context.Context) (migrationReceipt, error) {
	current, err := c.backend.inspect(ctx, c.options, bytes.Clone(c.record.identity))
	if err != nil || migrationContext(ctx) != nil || !current.exactNewPolicy || !validMasterIdentity(current.identity) || !bytes.Equal(current.identity, c.record.identity) {
		return c.unknown()
	}
	if err := c.journal.markVerified(ctx, c.recordCopy()); err != nil || migrationContext(ctx) != nil {
		return c.unknown()
	}
	c.record.state = migrationVerified
	c.state = migrationVerified
	return c.receipt(), nil
}

// Reconciliation is an explicit native-human metadata read, never mutation,
// replay or rollback. An old-looking policy cannot clear the unknown barrier.
// New coordinator instances restore the private journal item reference first.
func (c *migrationCoordinator) reconcile(ctx context.Context) (migrationReceipt, error) {
	if err := migrationContext(ctx); err != nil {
		return migrationReceipt{State: migrationBlocked}, err
	}
	if c == nil {
		return migrationReceipt{State: migrationBlocked}, errMigrationUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := migrationContext(ctx); err != nil {
		return c.receipt(), err
	}
	if c.state == migrationIdle {
		if err := c.load(ctx); err != nil {
			return c.unavailable()
		}
	}
	if c.state != migrationUnknown || c.record == nil {
		return c.receipt(), errMigrationUnavailable
	}
	return c.verify(ctx)
}
func (c *migrationCoordinator) String() string {
	if c == nil {
		return "Keychain custody migration unavailable"
	}
	return "Keychain custody migration"
}
func (c *migrationCoordinator) GoString() string               { return c.String() }
func (c *migrationCoordinator) Format(state fmt.State, _ rune) { _, _ = fmt.Fprint(state, c.String()) }
func (*migrationCoordinator) MarshalJSON() ([]byte, error)     { return []byte(`{"state":"private"}`), nil }

func validMigrationRelocation(o migrationOptions) bool {
	if o.newCanonicalExecutable == "" {
		return true
	}
	return migrationPackagedPath(o.newCanonicalExecutable) && o.newCanonicalExecutable != o.canonicalExecutable && strings.HasSuffix(o.newCanonicalExecutable, "/Mechanize.app/Contents/Helpers/mechanize")
}
func (o migrationOptions) destinationExecutable() string {
	if o.newCanonicalExecutable != "" {
		return o.newCanonicalExecutable
	}
	return o.canonicalExecutable
}
