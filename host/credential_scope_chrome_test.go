package host

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
)

type credentialHostFixtureHooks struct {
	clientID          string
	successorClientID string
	origin            string
	storageRoot       func(string)
	configure         func(*credentialBrowserFixture)
	beforeStatus      func(*testing.T, *Host, context.Context, auth.Principal, gateway.CredentialRefInput, gateway.CredentialPrepareInput, *credentialBrowserFixture, *atomic.Int64)
	exercise          func(*testing.T, *Host, context.Context, auth.Principal, gateway.CredentialRefInput, gateway.CredentialPrepareInput, *credentialBrowserFixture, *atomic.Int64)
}

type protectionWorkerRequest struct {
	ID               int                               `json:"id"`
	Op               string                            `json:"op"`
	Scope            *chrome.CredentialProtectionScope `json:"scope,omitempty"`
	ControlLease     *chrome.Lease                     `json:"controlLease,omitempty"`
	BrowserAttemptID string                            `json:"browserAttemptID,omitempty"`
	TargetIdentity   *chrome.Identity                  `json:"targetIdentity,omitempty"`
}
type protectionWorkerResponse struct {
	ID                int             `json:"id"`
	OK                bool            `json:"ok"`
	Phase             string          `json:"phase"`
	Reason            string          `json:"reason"`
	Origin            string          `json:"origin"`
	SourceIdentity    chrome.Identity `json:"sourceIdentity"`
	TargetIdentity    chrome.Identity `json:"targetIdentity"`
	PublicIdentity    chrome.Identity `json:"publicIdentity"`
	ProcessPID        int             `json:"processPID"`
	ActivationUnknown bool            `json:"activationUnknown"`
	ReceiptRetained   bool            `json:"receiptRetained"`
	ActivationUpdates int             `json:"activationUpdates"`
	ActivationFocus   int             `json:"activationFocus"`
	Available         bool            `json:"available"`
	ContainsFixture   bool            `json:"containsFixture"`
	ReadCalls         int             `json:"readCalls"`
	LoginRouteSHA256  string          `json:"loginRouteSHA256"`
	SourcePresent     bool            `json:"sourcePresent"`
	OriginalRestored  bool            `json:"originalRestored"`
	Loading           bool            `json:"loading"`
	ActiveRoot        bool            `json:"activeRoot"`
	Protected         bool            `json:"protected"`
	Retired           bool            `json:"retired"`
	Forbidden         int             `json:"forbidden"`
}
type protectionWorkerBridge struct {
	t           *testing.T
	mu          sync.Mutex
	command     *exec.Cmd
	input       io.WriteCloser
	output      *bufio.Scanner
	next        int
	counts      map[string]int
	lastRefusal protectionWorkerResponse
}

func newProtectionWorkerBridge(t *testing.T) *protectionWorkerBridge {
	t.Helper()
	node, e := exec.LookPath("node")
	if e != nil {
		t.Fatal("Node fixture runtime unavailable")
	}
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(file))
	command := exec.Command(node, filepath.Join(root, "browser/playwright/test/protection-scope-host-peer.mjs"))
	command.Dir = root
	input, e := command.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	output, e := command.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	log, e := os.Create(filepath.Join(t.TempDir(), "worker.stderr"))
	if e != nil {
		t.Fatal(e)
	}
	command.Stderr = log
	if e = command.Start(); e != nil {
		t.Fatal(e)
	}
	bridge := &protectionWorkerBridge{t: t, command: command, input: input, output: bufio.NewScanner(output), counts: map[string]int{}}
	bridge.output.Buffer(make([]byte, 4096), 65536)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = bridge.call(ctx, protectionWorkerRequest{Op: "stop"})
		_ = input.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = log.Close()
	})
	return bridge
}
func (b *protectionWorkerBridge) call(ctx context.Context, request protectionWorkerRequest) (protectionWorkerResponse, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.next++
	request.ID = b.next
	b.counts[request.Op]++
	if ctx.Err() != nil {
		return protectionWorkerResponse{}, ctx.Err()
	}
	if e := json.NewEncoder(b.input).Encode(request); e != nil {
		return protectionWorkerResponse{}, fmt.Errorf("worker phase %s write failed", request.Op)
	}
	type reply struct {
		result protectionWorkerResponse
		err    error
	}
	done := make(chan reply, 1)
	go func() {
		var r protectionWorkerResponse
		if !b.output.Scan() {
			done <- reply{err: errors.New("worker fixture closed")}
			return
		}
		e := json.Unmarshal(b.output.Bytes(), &r)
		done <- reply{r, e}
	}()
	select {
	case <-ctx.Done():
		_ = b.command.Process.Kill()
		return protectionWorkerResponse{}, ctx.Err()
	case got := <-done:
		if got.err != nil || got.result.ID != request.ID || got.result.Phase != request.Op {
			return protectionWorkerResponse{}, fmt.Errorf("worker phase %s closed reply invalid", request.Op)
		}
		if got.result.Forbidden != 0 {
			return got.result, fmt.Errorf("worker phase %s used forbidden input or renderer access", request.Op)
		}
		if !got.result.OK {
			b.lastRefusal = got.result
			b.t.Logf("production worker refusal: phase=%s reason=%s", got.result.Phase, got.result.Reason)
			return got.result, errors.New("production worker scope refused")
		}
		return got.result, nil
	}
}

func TestCredentialHostProductionWorkerLoadingSourceRecovery(t *testing.T) {
	if os.Getenv("MECHANIZE_REAL_CHROME_SCOPES") != "1" {
		t.Skip("set MECHANIZE_REAL_CHROME_SCOPES=1 for disposable Chrome production-worker integration")
	}
	bridge := newProtectionWorkerBridge(t)
	initCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	initial, e := bridge.call(initCtx, protectionWorkerRequest{Op: "init"})
	cancel()
	if e != nil {
		t.Fatal("fixture init", e)
	}
	if !strings.HasPrefix(initial.Origin, "https://") || initial.SourceIdentity.TabID <= 0 || initial.TargetIdentity.TabID <= 0 || initial.SourceIdentity.TabID == initial.TargetIdentity.TabID || initial.SourceIdentity.DocumentID == "" {
		t.Fatal("fixture must return actual HTTPS source and target identities")
	}
	scopes := map[string]chrome.CredentialProtectionScope{}
	var source chrome.CredentialProtectionScope
	useTarget := false
	configure := func(f *credentialBrowserFixture) {
		f.admissionTransform = func(ctx context.Context, a chrome.ControlAuthority) (chrome.ControlAuthority, error) {
			a.Document.Identity = initial.SourceIdentity
			a.BrokerEpoch = "fixture-broker"
			a.ChannelEpoch = "fixture-channel"
			a.ScopeHash = strings.Repeat("a", 64)
			if useTarget {
				// The exact target must pass the production worker's scope admission while
				// old source A remains loading. This is a metadata-only fixture preflight.
				if _, e := bridge.call(ctx, protectionWorkerRequest{Op: "disjoint", Scope: &source, TargetIdentity: &initial.TargetIdentity}); e != nil {
					return a, e
				}
				a.Document.Identity = initial.TargetIdentity
				a.Lease = chrome.Lease{ID: "target-lease", Generation: 2}
			}
			return a, nil
		}
		f.scopeCapture = func(ctx context.Context, a chrome.ControlAuthority, id string) (chrome.CredentialProtectionScope, error) {
			scope := chrome.CredentialProtectionScope{PreparationID: id, Identity: a.Document.Identity, Origin: a.Document.Origin, ChromeStartToken: a.Evidence.ChromeParent.StartToken, BrokerEpoch: a.BrokerEpoch, ChannelEpoch: a.ChannelEpoch, ScopeHash: a.ScopeHash}
			result, e := bridge.call(ctx, protectionWorkerRequest{Op: "capture", Scope: &scope, ControlLease: &a.Lease})
			if e != nil {
				return scope, e
			}
			scope.LoginRouteSHA256 = result.LoginRouteSHA256
			scopes[id] = scope
			if !useTarget {
				source = scope
			}
			return scope, nil
		}
		f.scopeAbsent = func(ctx context.Context, s chrome.CredentialProtectionScope) error {
			_, e := bridge.call(ctx, protectionWorkerRequest{Op: "absent", Scope: &s})
			return e
		}
		f.scopeRetire = func(ctx context.Context, s chrome.CredentialProtectionScope) error {
			out, e := bridge.call(ctx, protectionWorkerRequest{Op: "retire", Scope: &s})
			if e == nil && !out.Retired {
				return errors.New("worker did not retain retired scope")
			}
			return e
		}
		f.scopeDisjoint = func(ctx context.Context, s chrome.CredentialProtectionScope, target model.Surface) error {
			identity := initial.SourceIdentity
			if target.TabID == (chrome.Document{Identity: initial.TargetIdentity}).QualifiedTabID() {
				identity = initial.TargetIdentity
			}
			_, e := bridge.call(ctx, protectionWorkerRequest{Op: "disjoint", Scope: &s, TargetIdentity: &identity})
			return e
		}
	}
	exercise := func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
		original := f.session
		applied, e := h.CredentialApply(ctx, p, ref)
		if e != nil || applied.State != "filled" {
			t.Fatal("known fixture fill", applied, e)
		}
		f.submitUnknown = true
		submitted, e := h.CredentialSubmit(ctx, p, ref)
		if e != nil || submitted.State != "unknown" {
			t.Fatal("unknown fixture submit", submitted, e)
		}
		old := append([]data.CredentialDeliveryRecord(nil), original.attempts...)
		if len(old) != 2 || old[0].DispatchState != "dispatched" || old[1].DispatchState != "unknown" {
			t.Fatal("known and UNKNOWN durable children required")
		}
		input.Surface.TabID = (chrome.Document{Identity: initial.TargetIdentity}).QualifiedTabID()
		provisional, e := bridge.call(ctx, protectionWorkerRequest{Op: "loadingProvisional"})
		if e != nil || !provisional.Loading {
			t.Fatal("fixture provisional mode", e)
		}
		denied, e := h.CredentialPrepare(ctx, p, input)
		if e != nil || denied.State != "needsNativeAction" || denied.PreparationID != "" {
			t.Fatal("pre-commit source was not held", denied, e)
		}
		if blocked, e := h.durable.CredentialDeliveryBlocked(ctx, p); e != nil || !blocked {
			t.Fatal("provisional navigation retired protection", e)
		}
		committed, e := bridge.call(ctx, protectionWorkerRequest{Op: "loadingCommitted"})
		if e != nil || !committed.Loading {
			t.Fatal("fixture committed loading mode", e)
		}
		useTarget = true
		beforeReads := reads.Load()
		fills, submits := f.fills, f.submits
		started := time.Now()
		fresh, e := h.CredentialPrepare(ctx, p, input)
		if e != nil || fresh.State != "awaitingPreflight" || fresh.PreparationID == "" || fresh.PreparationID == ref.PreparationID {
			t.Fatal("committed loading source blocked new Prepare", fresh, e)
		}
		cleanupElapsed := time.Since(started)
		t.Logf("actual Host Prepare cleanup span: %s", cleanupElapsed)
		if cleanupElapsed > 6*time.Second {
			t.Fatal("source cleanup exceeded bounded operation")
		}
		bound := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: input.SessionID, Purpose: input.Purpose})
		e = h.durable.WithCredentialDeliveryComponents(bound, p, func(held context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
			prep, rows, e := h.durable.LoadCredentialRecovery(held, p, ref.PreparationID)
			if e != nil {
				return e
			}
			if prep.ProtectionState != "closed" || len(rows) != len(old) {
				t.Fatal("original history removed")
			}
			previous := map[string]data.CredentialDeliveryRecord{}
			for _, row := range old {
				previous[row.AttemptID] = row
			}
			for _, row := range rows {
				before, ok := previous[row.AttemptID]
				if !ok || row.DispatchState != before.DispatchState || row.DocumentID != before.DocumentID || row.TabID != before.TabID || row.SelectedRevision != before.SelectedRevision {
					t.Fatal("source cleanup changed dispatch history")
				}
				want := "closed"
				if row.DispatchState == "unknown" {
					want = "retired"
				}
				if row.ProtectionState != want || row.Revision != before.Revision+1 {
					t.Fatal("wrong protection-only transition")
				}
				before.ProtectionState = row.ProtectionState
				before.Revision = row.Revision
				before.UpdatedAt = row.UpdatedAt
				if row != before {
					t.Fatal("cleanup changed immutable delivery history")
				}
			}
			return nil
		})
		if e != nil {
			t.Fatal("retained durable history", e)
		}
		t.Logf("fresh explicit Prepare record validation reads=%d", reads.Load()-beforeReads)
		beforeReads = reads.Load()
		f.session = h.credentials.pending[fresh.PreparationID]
		newRef := gateway.CredentialRefInput{SessionID: input.SessionID, PreparationID: fresh.PreparationID}
		ready, e := h.CredentialStatus(ctx, p, newRef)
		if e != nil || ready.State != "ready" {
			t.Fatal("production worker B preflight blocked", ready, e)
		}
		if scopes[fresh.PreparationID].Identity != initial.TargetIdentity {
			t.Fatal("fresh preparation lost exact target metadata")
		}
		if f.fills != fills || f.submits != submits || reads.Load() != beforeReads {
			t.Fatal("cleanup or B preflight replayed/decrypted credentials")
		}
		state, e := bridge.call(ctx, protectionWorkerRequest{Op: "state"})
		if e != nil || !state.Loading || state.SourcePresent || !state.ActiveRoot {
			t.Fatal("old committed tab stopped loading or regained protected source during Prepare", e)
		}
		restored, e := bridge.call(ctx, protectionWorkerRequest{Op: "restoreSource"})
		if e != nil || !restored.Protected || !restored.OriginalRestored || !restored.SourcePresent {
			t.Fatal("restored login route lost production worker protection", e)
		}
		t.Logf("restoration metadata: originalRestored=%t sourcePresent=%t", restored.OriginalRestored, restored.SourcePresent)
		current := auth.WithConsentBinding(ctx, f.session.consent)
		disjointBefore := bridge.counts["disjoint"]
		lease, e := h.AuthorizeOperation(current, p, model.Surface{Kind: "web", Origin: input.Surface.Origin, TabID: (chrome.Document{Identity: initial.SourceIdentity}).QualifiedTabID()}, false, consent.Observe)
		if e == nil {
			lease.Release()
			t.Fatal("restored protected login document admitted by Host")
		}
		if bridge.counts["disjoint"] <= disjointBefore || bridge.lastRefusal.Phase != "disjoint" || bridge.lastRefusal.Reason != "scopeTargetProtected" {
			t.Fatal("Host refusal did not come from production worker restored-source protection", bridge.lastRefusal.Phase, bridge.lastRefusal.Reason)
		}
		if f.fills != fills || f.submits != submits || reads.Load() != beforeReads {
			t.Fatal("restored source refusal caused private input")
		}
		t.Logf("production worker closed phases: capture=%d absent=%d retire=%d disjoint=%d; retained known=1 unknown=1", bridge.counts["capture"], bridge.counts["absent"], bridge.counts["retire"], bridge.counts["disjoint"])
	}
	credentialHostFixtureFlow(t, "productionWorkerLoading", credentialHostFixtureHooks{origin: initial.Origin, configure: configure, exercise: exercise})
}
