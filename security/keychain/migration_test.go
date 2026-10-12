package keychain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
)

const migrationPrivateCanary = "private-backend-policy-and-error-canary"

type migrationBackendFixture struct {
	events       *[]string
	prepareError bool
	verifyError  bool
	commitError  bool
	inspectError bool
	badIdentity  bool
	substitute   bool
	newPolicy    bool
	prepareHook  func(*migrationPrepared)
	verifyHook   func(*migrationPrepared)
	commitHook   func()
	inspectHook  func()
	prepares     int
	commits      int
	inspections  int
	disposals    int
}

func (b *migrationBackendFixture) event(s string) { *b.events = append(*b.events, s) }
func (b *migrationBackendFixture) prepare(context.Context, migrationOptions) (*migrationPrepared, error) {
	b.prepares++
	b.event("prepare")
	p := &migrationPrepared{identity: []byte("synthetic-persistent-item"), handle: migrationPrivateCanary, dispose: func() { b.disposals++ }}
	if b.badIdentity {
		p.identity = make([]byte, 16385)
	}
	if b.prepareHook != nil {
		b.prepareHook(p)
	}
	if b.prepareError {
		return p, errors.New(migrationPrivateCanary)
	}
	return p, nil
}
func (b *migrationBackendFixture) verifyBeforeCommit(_ context.Context, _ migrationOptions, p *migrationPrepared) error {
	b.event("verify-pins-and-old-policy")
	if b.verifyHook != nil {
		b.verifyHook(p)
	}
	if b.verifyError {
		return errors.New(migrationPrivateCanary)
	}
	return nil
}
func (b *migrationBackendFixture) commit(context.Context, migrationOptions, *migrationPrepared) error {
	b.event("commit")
	b.commits++
	if b.commitHook != nil {
		b.commitHook()
	}
	if b.commitError {
		return errors.New(migrationPrivateCanary)
	}
	return nil
}
func (b *migrationBackendFixture) inspect(_ context.Context, _ migrationOptions, identity []byte) (migrationInspection, error) {
	b.event("inspect")
	b.inspections++
	if b.inspectHook != nil {
		b.inspectHook()
	}
	if b.inspectError {
		return migrationInspection{}, errors.New(migrationPrivateCanary)
	}
	if b.substitute {
		identity = []byte("substituted-item")
	}
	return migrationInspection{identity: identity, exactNewPolicy: b.newPolicy}, nil
}

type migrationJournalFixture struct {
	mu                                     sync.Mutex
	events                                 *[]string
	record                                 *migrationJournalRecord
	loadError, unknownError, verifiedError bool
	unknownHook                            func()
	verifiedHook                           func()
}

func (j *migrationJournalFixture) load(context.Context) (*migrationJournalRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	*j.events = append(*j.events, "load")
	if j.loadError {
		return nil, errors.New(migrationPrivateCanary)
	}
	if j.record == nil {
		return nil, nil
	}
	copy := *j.record
	copy.identity = bytes.Clone(copy.identity)
	return &copy, nil
}
func (j *migrationJournalFixture) markUnknown(_ context.Context, record migrationJournalRecord) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	*j.events = append(*j.events, "journal-unknown")
	if j.unknownHook != nil {
		j.unknownHook()
	}
	if j.unknownError || j.record != nil {
		return errors.New(migrationPrivateCanary)
	}
	copy := record
	copy.identity = bytes.Clone(record.identity)
	j.record = &copy
	return nil
}
func (j *migrationJournalFixture) markVerified(_ context.Context, record migrationJournalRecord) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	*j.events = append(*j.events, "journal-verified")
	if j.verifiedHook != nil {
		j.verifiedHook()
	}
	if j.verifiedError || j.record == nil || !reflect.DeepEqual(*j.record, record) {
		return errors.New(migrationPrivateCanary)
	}
	j.record.state = migrationVerified
	return nil
}
func migrationFixtureOptions() migrationOptions {
	return migrationOptions{canonicalExecutable: "/private/synthetic/Mechanize/mechanize", alias: "vault-master-v1",
		oldRequirement: `identifier "com.viant.mechanize.broker" and cdhash H"` + strings.Repeat("1", 40) + `"`,
		newRequirement: `identifier "com.viant.mechanize.broker" and cdhash H"` + strings.Repeat("2", 40) + `"`,
		item:           Item{Service: "com.viant.mechanize.vault", Account: "synthetic-enrolled-account"}}
}
func migrationFixture(t *testing.T) (*migrationCoordinator, *migrationBackendFixture, *migrationJournalFixture, *[]string) {
	t.Helper()
	events := &[]string{}
	b := &migrationBackendFixture{events: events, newPolicy: true}
	j := &migrationJournalFixture{events: events}
	approve := func(_ context.Context, transition migrationTransition) (migrationApproval, error) {
		*events = append(*events, "local-approval")
		return migrationApproval{approved: true, binding: transition.Binding}, nil
	}
	c, err := newMigrationCoordinator(migrationFixtureOptions(), b, j, approve)
	if err != nil {
		t.Fatal(err)
	}
	return c, b, j, events
}
func migrationFixtureContext(t *testing.T, human bool) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(masterFixtureContext(t, human), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}
func prepareMigrationFixture(t *testing.T, c *migrationCoordinator, ctx context.Context) migrationReceipt {
	t.Helper()
	result, err := c.prepare(ctx)
	if err != nil || result.State != migrationPreparedState {
		t.Fatalf("preparation failed: %v", err)
	}
	return result
}
func TestMigrationKnownSuccessRequiresOrderedWriteAheadApprovalAndSameItemVerification(t *testing.T) {
	c, b, j, events := migrationFixture(t)
	ctx := migrationFixtureContext(t, true)
	prepared := prepareMigrationFixture(t, c, ctx)
	result, err := c.commit(ctx)
	want := []string{"load", "prepare", "verify-pins-and-old-policy", "local-approval", "journal-unknown", "commit", "inspect", "journal-verified"}
	if err != nil || result.State != migrationVerified || result.TransitionID != prepared.TransitionID || !reflect.DeepEqual(*events, want) || b.commits != 1 || b.disposals != 1 || j.record.state != migrationVerified {
		t.Fatalf("invalid successful transition: %v %v", result, err)
	}
	if _, err = c.commit(ctx); err == nil || b.commits != 1 {
		t.Fatal("verified transition replayed")
	}
}
func TestMigrationRequiresNativeHumanAndBoundedContextBeforePrepareAndCommit(t *testing.T) {
	for _, mode := range []string{"untrusted", "unbounded", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			c, b, _, _ := migrationFixture(t)
			ctx := migrationFixtureContext(t, mode != "untrusted")
			if mode == "unbounded" {
				ctx = masterFixtureContext(t, true)
			}
			if mode == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := c.prepare(ctx); err == nil || b.prepares != 0 {
				t.Fatal("invalid context prepared migration")
			}
			prepareMigrationFixture(t, c, migrationFixtureContext(t, true))
			if _, err := c.commit(ctx); err == nil || b.commits != 0 {
				t.Fatal("invalid context dispatched migration")
			}
		})
	}
}
func TestMigrationRefusesInvalidTrustedConfiguration(t *testing.T) {
	c, b, j, _ := migrationFixture(t)
	cases := []func(*migrationOptions){
		func(o *migrationOptions) { o.canonicalExecutable = "relative" },
		func(o *migrationOptions) { o.canonicalExecutable = "/a/../b" },
		func(o *migrationOptions) { o.oldRequirement = "anchor apple" },
		func(o *migrationOptions) { o.newRequirement = o.oldRequirement },
		func(o *migrationOptions) {
			o.newRequirement = strings.Replace(o.newRequirement, ".broker", ".other", 1)
		},
		func(o *migrationOptions) { o.alias = "../item" },
		func(o *migrationOptions) { o.item.Service = "other" },
		func(o *migrationOptions) { o.item.Account = "" },
		func(o *migrationOptions) { o.item.Account = "line\nbreak" },
	}
	for _, alter := range cases {
		options := migrationFixtureOptions()
		alter(&options)
		if _, err := newMigrationCoordinator(options, b, j, c.approve); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	if _, err := newMigrationCoordinator(migrationFixtureOptions(), b, j, nil); err == nil {
		t.Fatal("missing independent approval accepted")
	}
}
func TestMigrationPreparationFailuresNeverDispatchOrExposeBackendErrors(t *testing.T) {
	for _, mode := range []string{"journal", "prepare", "identity", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			c, b, j, _ := migrationFixture(t)
			ctx, cancel := context.WithCancel(migrationFixtureContext(t, true))
			defer cancel()
			switch mode {
			case "journal":
				j.loadError = true
			case "prepare":
				b.prepareError = true
			case "identity":
				b.badIdentity = true
			case "cancel":
				b.prepareHook = func(*migrationPrepared) { cancel() }
			}
			result, err := c.prepare(ctx)
			if err != errMigrationUnavailable || result.State != migrationBlocked || b.commits != 0 {
				t.Fatal("preparation failure did not refuse")
			}
			if _, err = c.prepare(migrationFixtureContext(t, true)); err == nil {
				t.Fatal("failed preparation retried")
			}
			if b.prepares > 0 && b.disposals != 1 {
				t.Fatal("preparation handle was retained")
			}
		})
	}
}
func TestMigrationDeniedStaleOrMissingIndependentApprovalCannotDispatch(t *testing.T) {
	for _, mode := range []string{"denied", "stale-binding", "error", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			c, b, j, _ := migrationFixture(t)
			ctx, cancel := context.WithCancel(migrationFixtureContext(t, true))
			defer cancel()
			prepareMigrationFixture(t, c, ctx)
			c.approve = func(_ context.Context, transition migrationTransition) (migrationApproval, error) {
				if mode == "error" {
					return migrationApproval{}, errors.New(migrationPrivateCanary)
				}
				if mode == "cancel" {
					cancel()
				}
				binding := transition.Binding
				if mode == "stale-binding" {
					binding = strings.Repeat("0", 64)
				}
				return migrationApproval{approved: mode != "denied", binding: binding}, nil
			}
			result, err := c.commit(ctx)
			if err != errMigrationUnavailable || result.State != migrationBlocked || b.commits != 0 || j.record != nil {
				t.Fatal("approval refusal did not block")
			}
		})
	}
}
func TestMigrationApprovalBindsEveryTransitionFieldAndPersistentIdentity(t *testing.T) {
	c, _, _, _ := migrationFixture(t)
	prepareMigrationFixture(t, c, migrationFixtureContext(t, true))
	original := c.transition()
	if !validMigrationID(original.Binding) || original.ItemReferenceSHA256 != migrationDigest(c.record.identity) {
		t.Fatal("unbounded approval binding")
	}
	for _, alter := range []func(){
		func() { c.options.canonicalExecutable += "-other" }, func() { c.options.oldRequirement += "x" }, func() { c.options.newRequirement += "x" },
		func() { c.options.alias += "x" }, func() { c.options.item.Service += "x" }, func() { c.options.item.Account += "x" },
		func() { c.record.identity = []byte("another-item") }, func() { c.record.transitionID = strings.Repeat("f", 64) },
	} {
		savedOptions, savedRecord := c.options, c.recordCopy()
		alter()
		if c.transition().Binding == original.Binding {
			t.Fatal("approval omitted transition field")
		}
		c.options = savedOptions
		c.record = &savedRecord
	}
}
func TestMigrationPinPolicyIdentityOrCancellationFailureBeforeDispatchBlocks(t *testing.T) {
	for _, mode := range []string{"pins-policy", "identity", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			c, b, j, _ := migrationFixture(t)
			ctx, cancel := context.WithCancel(migrationFixtureContext(t, true))
			defer cancel()
			prepareMigrationFixture(t, c, ctx)
			switch mode {
			case "pins-policy":
				b.verifyError = true
			case "identity":
				b.verifyHook = func(p *migrationPrepared) { p.identity = []byte("substitution") }
			case "cancel":
				b.verifyHook = func(*migrationPrepared) { cancel() }
			}
			result, err := c.commit(ctx)
			if err != errMigrationUnavailable || result.State != migrationBlocked || b.commits != 0 || j.record != nil {
				t.Fatal("precommit substitution or refusal accepted")
			}
		})
	}
}
func TestMigrationJournalFailureOrCancellationNeverDispatchesAndLatchesUnknown(t *testing.T) {
	for _, mode := range []string{"write-error", "cancel-after-write"} {
		t.Run(mode, func(t *testing.T) {
			c, b, j, _ := migrationFixture(t)
			ctx, cancel := context.WithCancel(migrationFixtureContext(t, true))
			defer cancel()
			prepareMigrationFixture(t, c, ctx)
			if mode == "write-error" {
				j.unknownError = true
			} else {
				j.unknownHook = cancel
			}
			result, err := c.commit(ctx)
			if err != errMigrationUnknown || result.State != migrationUnknown || b.commits != 0 {
				t.Fatal("uncertain journal dispatched mutation")
			}
			if _, err = c.commit(migrationFixtureContext(t, true)); err == nil || b.commits != 0 {
				t.Fatal("unknown was replayed")
			}
		})
	}
}
func TestMigrationEveryPostDispatchFailureRemainsUnknownWithoutRetryOrReversal(t *testing.T) {
	for _, mode := range []string{"lost-ack", "cancel-commit", "inspect-error", "substitution", "old-policy", "verified-journal-error", "cancel-inspect", "cancel-verified-journal"} {
		t.Run(mode, func(t *testing.T) {
			c, b, j, _ := migrationFixture(t)
			ctx, cancel := context.WithCancel(migrationFixtureContext(t, true))
			defer cancel()
			prepareMigrationFixture(t, c, ctx)
			switch mode {
			case "lost-ack":
				b.commitError = true
			case "cancel-commit":
				b.commitHook = cancel
			case "inspect-error":
				b.inspectError = true
			case "substitution":
				b.substitute = true
			case "old-policy":
				b.newPolicy = false
			case "verified-journal-error":
				j.verifiedError = true
			case "cancel-inspect":
				b.inspectHook = cancel
			case "cancel-verified-journal":
				j.verifiedHook = cancel
			}
			result, err := c.commit(ctx)
			if err != errMigrationUnknown || result.State != migrationUnknown || b.commits != 1 || b.disposals != 1 {
				t.Fatal("postdispatch uncertainty was lost")
			}
			if _, err = c.commit(migrationFixtureContext(t, true)); err == nil || b.commits != 1 {
				t.Fatal("unknown mutation replayed")
			}
		})
	}
}
func TestMigrationRestartRestoresBarrierAndReconcilesOnlyExactNewSameItem(t *testing.T) {
	c, b, j, _ := migrationFixture(t)
	ctx := migrationFixtureContext(t, true)
	prepareMigrationFixture(t, c, ctx)
	b.commitError = true
	if _, err := c.commit(ctx); err != errMigrationUnknown {
		t.Fatal("missing unknown barrier")
	}
	restarted, err := newMigrationCoordinator(c.options, b, j, c.approve)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := restarted.prepare(ctx); err != errMigrationUnknown || result.State != migrationUnknown || b.prepares != 1 {
		t.Fatal("restart replayed preparation")
	}
	b.newPolicy = false
	if _, err = restarted.reconcile(ctx); err != errMigrationUnknown || b.commits != 1 {
		t.Fatal("old policy cleared unknown")
	}
	b.newPolicy = true
	b.substitute = true
	if _, err = restarted.reconcile(ctx); err != errMigrationUnknown {
		t.Fatal("different item cleared unknown")
	}
	b.substitute = false
	if result, err := restarted.reconcile(ctx); err != nil || result.State != migrationVerified || b.commits != 1 || j.record.state != migrationVerified {
		t.Fatal("metadata reconciliation failed")
	}
	if _, err = restarted.commit(ctx); err == nil || b.commits != 1 {
		t.Fatal("reconciliation enabled replay")
	}
}
func TestMigrationForeignMalformedAndVerifiedJournalsNeverPrepare(t *testing.T) {
	for _, mode := range []string{"foreign", "malformed-id", "oversized-item", "wrong-state", "verified"} {
		t.Run(mode, func(t *testing.T) {
			c, b, j, _ := migrationFixture(t)
			j.record = &migrationJournalRecord{state: migrationUnknown, transitionID: strings.Repeat("1", 64), optionsSHA256: migrationOptionsDigest(c.options), identity: []byte("fixture")}
			switch mode {
			case "foreign":
				j.record.optionsSHA256 = "other"
			case "malformed-id":
				j.record.transitionID = "x"
			case "oversized-item":
				j.record.identity = make([]byte, 16385)
			case "wrong-state":
				j.record.state = migrationIdle
			case "verified":
				j.record.state = migrationVerified
			}
			if _, err := c.prepare(migrationFixtureContext(t, true)); err == nil || b.prepares != 0 {
				t.Fatal("journal allowed migration")
			}
		})
	}
}
func TestMigrationTwoPreparedCoordinatorsCannotBothDispatch(t *testing.T) {
	first, b, j, _ := migrationFixture(t)
	second, err := newMigrationCoordinator(first.options, b, j, first.approve)
	if err != nil {
		t.Fatal(err)
	}
	ctx := migrationFixtureContext(t, true)
	prepareMigrationFixture(t, first, ctx)
	prepareMigrationFixture(t, second, ctx)
	if _, err = first.commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = second.commit(ctx); err != errMigrationUnknown || b.commits != 1 {
		t.Fatal("journal failed process exclusion")
	}
}
func TestMigrationResultsAndFormattingNeverExposePrivateBackendState(t *testing.T) {
	c, b, _, _ := migrationFixture(t)
	ctx := migrationFixtureContext(t, true)
	prepared := prepareMigrationFixture(t, c, ctx)
	b.commitError = true
	result, err := c.commit(ctx)
	encoded, _ := json.Marshal([]migrationReceipt{prepared, result})
	privateJSON, _ := json.Marshal(c)
	text := string(encoded) + string(privateJSON) + fmt.Sprintf("%v %+v %#v %v", c, c, c, err)
	if strings.Contains(text, migrationPrivateCanary) || strings.Contains(text, "synthetic-persistent-item") || strings.Contains(text, c.options.item.Account) {
		t.Fatal("public output contained private state")
	}
	if err != errMigrationUnknown {
		t.Fatal("backend error was not closed")
	}
}
func TestMigrationReconciliationRequiresNativeHumanAndDeadline(t *testing.T) {
	c, b, _, _ := migrationFixture(t)
	ctx := migrationFixtureContext(t, true)
	prepareMigrationFixture(t, c, ctx)
	b.commitError = true
	_, _ = c.commit(ctx)
	if _, err := c.reconcile(migrationFixtureContext(t, false)); err != auth.ErrUnauthorized || b.inspections != 0 {
		t.Fatal("untrusted reconciliation inspected item")
	}
	if _, err := c.reconcile(masterFixtureContext(t, true)); err != errMigrationUnavailable || b.inspections != 0 {
		t.Fatal("unbounded reconciliation inspected item")
	}
}

func TestMigrationConcurrentCommitDispatchesAtMostOnce(t *testing.T) {
	c, b, _, _ := migrationFixture(t)
	ctx := migrationFixtureContext(t, true)
	prepareMigrationFixture(t, c, ctx)
	var group sync.WaitGroup
	errorsSeen := make(chan error, 2)
	for range 2 {
		group.Add(1)
		go func() { defer group.Done(); _, err := c.commit(ctx); errorsSeen <- err }()
	}
	group.Wait()
	close(errorsSeen)
	successes := 0
	for err := range errorsSeen {
		if err == nil {
			successes++
		}
	}
	if successes != 1 || b.commits != 1 || b.disposals != 1 {
		t.Fatal("concurrent commit replayed transition")
	}
}
