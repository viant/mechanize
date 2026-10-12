package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	sessionpkg "github.com/viant/mechanize/session"
	"github.com/viant/mechanize/vault"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/jwt/verifier"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type credentialFixtureKey struct{ calls *atomic.Int64 }

func (k credentialFixtureKey) Resolve(context.Context, string) ([]byte, error) {
	if k.calls != nil {
		k.calls.Add(1)
	}
	return bytes.Repeat([]byte{29}, 32), nil
}
func TestCredentialHostCompositionReusableConsentAndDurableFailedProbe(t *testing.T) {
	for _, mode := range []string{"preflightRetire", "preflightRetireRestart", "preflightRetireBusy", "scopeDisjoint", "scopeCleanup", "scopeCleanupUnknown", "scopeCleanupAbsentFail", "scopeCleanupLateFail", "scopeCleanupTimeout", "scopeCleanupPinned", "scopeCleanupManualStaging", "scopeCleanupManualStagingUnknown", "scopeCleanupManualStagingAbsentFail", "unavailable", "known", "unknown", "cancel", "privacyCandidate", "sessionClose", "sessionRecover", "restartRecovery", "restartRecoveryUnknown", "closeDuringFill", "challenge", "expiredChallenge", "missingEndpoint", "wrongEndpoint", "ambiguousEndpoint", "expiredUndispatched", "revokedControl", "candidateMissing", "postPending", "postRejected"} {
		t.Run(mode, func(t *testing.T) { credentialHostFixtureFlow(t, mode) })
	}
}
func credentialHostFixtureFlow(t *testing.T, mode string, hooks ...credentialHostFixtureHooks) {
	origin := "https://fixture.invalid"
	var hook credentialHostFixtureHooks
	if len(hooks) > 1 {
		t.Fatal("one fixture hook required")
	}
	if len(hooks) == 1 {
		hook = hooks[0]
		if hook.origin != "" {
			origin = hook.origin
		}
	}
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if hook.storageRoot != nil {
		hook.storageRoot(root)
	}
	key := filepath.Join(root, "fixture-hmac")
	if e = os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32))), 0600); e != nil {
		t.Fatal(e)
	}
	_, file, _, _ := runtime.Caller(0)
	h, e := New(context.Background(), Config{SourceRoot: filepath.Dir(filepath.Dir(file)), StorageRoot: root, Keys: verifier.Config{HMAC: &scy.Resource{URL: key}}, IdentityPolicy: auth.Policy{Issuer: "fixture", Audience: "mechanize", Algorithms: []string{"HS256"}, Clients: map[string]string{"fixture-agent": "Fixture"}}, Users: []User{{Subject: "actor", DesktopAccess: true}}})
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close(context.Background())
	if h.credentials == nil || h.credentials.host != h {
		t.Fatal("production host did not compose private service")
	}
	p, _ := auth.NewPrincipal("fixture", "", "actor", []string{"desktop:control", "desktop:observe", "consent:admin"})
	p.ClientID = "fixture-agent"
	p.ClientName = "Fixture"
	ctx := auth.WithPrincipal(context.Background(), p)
	human, _ := auth.WithNativeHuman(ctx)
	session, e := h.Runtime.Open(ctx, "private fixture")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.CredentialPrepare(ctx, p, gateway.CredentialPrepareInput{SessionID: session.SessionID, Purpose: "login", Surface: model.Surface{Kind: "web", Origin: origin}}); e == nil {
		t.Fatal("absent production provider admitted")
	}
	// Only synthetic providers are installed below; the real host methods, consent
	// service, durable components, RecordStore and Manager are exercised unchanged.
	recordRoot := filepath.Join(root, "records")
	if e = os.Mkdir(recordRoot, 0700); e != nil {
		t.Fatal(e)
	}
	vaultReads := &atomic.Int64{}
	h.nativeVaultRecords, e = vault.NewRecordStore(recordRoot, "fixture-v1", &vault.Cipher{Keys: credentialFixtureKey{calls: vaultReads}})
	if e != nil {
		t.Fatal(e)
	}
	h.vaultExposure, e = vault.NewGuardedExposureGate(func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	h.chrome, e = chrome.NewGateway(&chrome.Broker{}, chrome.GatewayOptions{})
	if e != nil {
		t.Fatal(e)
	}
	defer func() { h.chrome = nil }()
	values, _ := vault.NewRecordValues([]byte("record-key-canary"), [][2][]byte{{[]byte("$scy.type"), []byte("basic")}, {[]byte("endpoint"), []byte(origin + "/")}, {[]byte("username"), []byte("username-secret-canary")}, {[]byte("password"), []byte("password-secret-canary")}})
	meta, e := h.nativeVaultRecords.Create(human, values)
	if e != nil {
		t.Fatal(e)
	}
	beforeUnauthorizedReads := vaultReads.Load()
	if _, err := h.CredentialPrepare(ctx, p, gateway.CredentialPrepareInput{SessionID: session.SessionID, Purpose: "login", Surface: model.Surface{Kind: "web", Origin: origin}}); err == nil {
		t.Fatal("saved credential bypassed missing control consent")
	}
	if vaultReads.Load() != beforeUnauthorizedReads {
		t.Fatal("missing control consent decrypted saved credentials")
	}

	request, e := h.consent.Request(ctx, p, session.SessionID, consent.RequestInput{Scope: consent.Scope{Kind: "desktop"}, Modes: []consent.Mode{consent.Control, consent.Observe}, Purpose: "private fixture", DurationSeconds: 60})
	if e != nil {
		t.Fatal(e)
	}
	decide, _ := json.Marshal(map[string]any{"requestID": request.ID, "decision": consent.AllowUntilRevoked})
	if _, e = h.consent.NativeRPC(human, "decide", decide); e != nil {
		t.Fatal(e)
	}
	input := gateway.CredentialPrepareInput{SessionID: session.SessionID, Purpose: "login", Surface: model.Surface{Kind: "web", Origin: origin}}
	switch mode {
	case "missingEndpoint":
		if err := h.nativeVaultRecords.Delete(human, meta.Reference, meta.Revision); err != nil {
			t.Fatal(err)
		}
	case "wrongEndpoint":
		input.Surface.Origin = "https://other.invalid"
	case "ambiguousEndpoint":
		duplicate, _ := vault.NewRecordValues([]byte("second-record-key-canary"), [][2][]byte{{[]byte("$scy.type"), []byte("basic")}, {[]byte("endpoint"), []byte(origin)}, {[]byte("username"), []byte("username-secret-canary")}, {[]byte("password"), []byte("password-secret-canary")}})
		if _, err := h.nativeVaultRecords.Create(human, duplicate); err != nil {
			t.Fatal(err)
		}
	}
	prepared, e := h.CredentialPrepare(ctx, p, input)
	if mode == "missingEndpoint" || mode == "wrongEndpoint" || mode == "ambiguousEndpoint" {
		if e != nil || prepared.State != "needsConfiguration" {
			t.Fatal("ineligible endpoint selected", prepared, e)
		}
		ref := gateway.CredentialRefInput{SessionID: session.SessionID, PreparationID: prepared.PreparationID}
		for _, operation := range []func(context.Context, auth.Principal, gateway.CredentialRefInput) (gateway.CredentialResult, error){h.CredentialStatus, h.CredentialApply, h.CredentialSubmit} {
			result, err := operation(ctx, p, ref)
			if err != nil || result.State != "needsConfiguration" {
				t.Fatal("configuration became native approval or input", result, err)
			}
		}
		again, err := h.CredentialPrepare(ctx, p, input)
		if err != nil || again.State != "needsConfiguration" || again.PreparationID == prepared.PreparationID {
			t.Fatal("configuration retry blocked", again, err)
		}
		return
	}
	if mode == "expiredUndispatched" {
		old := h.credentials.pending[prepared.PreparationID]
		old.expires = time.Now().Add(-time.Second)
		fresh, err := h.CredentialPrepare(ctx, p, input)
		if err != nil || fresh.State != "awaitingPreflight" || fresh.PreparationID == prepared.PreparationID || h.credentials.pending[prepared.PreparationID] != nil || old.done.Err() == nil {
			t.Fatal("expired never-dispatched request blocked retry", fresh, err)
		}
		return
	}
	if mode == "revokedControl" {
		item := h.credentials.pending[prepared.PreparationID]
		revoke, _ := json.Marshal(map[string]string{"grantID": item.consent.GrantID})
		if _, err := h.consent.NativeRPC(human, "revoke", revoke); err != nil {
			t.Fatal(err)
		}
		ref := gateway.CredentialRefInput{SessionID: session.SessionID, PreparationID: prepared.PreparationID}
		result, err := h.CredentialStatus(ctx, p, ref)
		if err != nil || result.State != "needsNativeAction" || len(item.attempts) != 0 || item.preparation != nil {
			t.Fatal("revoked control admitted preflight/input", result, err)
		}
		if _, err := h.CredentialPrepare(ctx, p, input); err == nil {
			t.Fatal("revoked control admitted new credential selection")
		}
		return
	}
	if e != nil || prepared.State != "awaitingPreflight" {
		t.Fatal(prepared, e)
	}
	if _, e = h.CredentialPrepare(ctx, p, input); e == nil {
		t.Fatal("duplicate pending selection")
	}
	ref := gateway.CredentialRefInput{SessionID: session.SessionID, PreparationID: prepared.PreparationID}
	if result, e := h.CredentialApply(ctx, p, ref); e != nil || result.State != "awaitingPreflight" {
		t.Fatal("apply skipped explicit preflight", result, e)
	}
	bind, _ := json.Marshal(map[string]string{"sessionID": "native-session", "id": prepared.PreparationID, "recordId": meta.Reference.ID, "revision": meta.Revision})
	if _, e = h.NativeInformation(ctx, "credential.bind", bind); e == nil {
		t.Fatal("web actor obtained native approval")
	}
	if _, e = h.NativeInformation(human, "credential.bind", bind); e == nil {
		t.Fatal("caller-selected record authority remains available")
	}
	if _, e = h.NativeInformation(human, "credential.bind", bind); e == nil {
		t.Fatal("native approval replay")
	}
	if waiting, e := h.CredentialApply(ctx, p, ref); e != nil || waiting.State != "awaitingPreflight" {
		t.Fatal("apply skipped explicit private preflight", waiting, e)
	}
	if mode == "cancel" {
		canceledFlow := h.credentials.pending[prepared.PreparationID]
		cancelRaw, _ := json.Marshal(map[string]string{"sessionID": "native-session", "id": prepared.PreparationID})
		if _, e = h.NativeInformation(ctx, "credential.cancel", cancelRaw); e == nil {
			t.Fatal("web actor canceled native selection")
		}
		if _, e = h.NativeInformation(human, "credential.cancel", cancelRaw); e != nil {
			t.Fatal(e)
		}
		if canceledFlow.done.Err() == nil {
			t.Fatal("native cancellation did not inhibit flow")
		}
		if _, e = h.NativeInformation(human, "credential.bind", bind); e == nil {
			t.Fatal("canceled native selection rebound")
		}
		if _, e = h.CredentialApply(ctx, p, ref); e == nil {
			r, _ := h.CredentialStatus(ctx, p, ref)
			if r.State != "needsNativeAction" {
				t.Fatal("canceled flow dispatched")
			}
		}
		if blocked, e := h.durable.CredentialDeliveryBlocked(ctx, p); e != nil || blocked {
			t.Fatal("pre-probe cancellation invented effect")
		}
		if restarted, e := h.CredentialPrepare(ctx, p, input); e != nil || restarted.State != "awaitingPreflight" || restarted.PreparationID == prepared.PreparationID {
			t.Fatal("pre-probe native cancellation prevented a new explicit preparation", e)
		}
		return
	}
	fixture := &credentialBrowserFixture{host: h, session: h.credentials.pending[ref.PreparationID], t: t, unknown: mode == "unknown" || mode == "restartRecoveryUnknown" || mode == "scopeCleanupUnknown" || mode == "scopeCleanupLateFail" || mode == "scopeCleanupManualStagingUnknown", privacyCandidate: mode == "privacyCandidate", challenge: mode == "challenge" || mode == "expiredChallenge", unavailable: mode == "unavailable" || strings.HasPrefix(mode, "preflightRetire")}
	h.credentials.browserFixture = fixture
	if hook.configure != nil {
		hook.configure(fixture)
	}
	if mode == "inspectionChallenge" {
		fixture.inspectionFailure = "challenge"
	}
	if mode == "postPending" {
		fixture.postStage = "pending"
	}
	if mode == "postRejected" {
		fixture.postStage = "rejected"
	}
	if mode == "candidateMissing" {
		probe := &credentialCandidateFixture{credentialBrowser: fixture}
		h.credentials.browserFixture = probe
		before := vaultReads.Load()
		waiting, e := h.CredentialStatus(ctx, p, ref)
		if e != nil || waiting.State != "awaitingPreflight" || waiting.AttentionCode != "privateBrowserAdmission" || fixture.admissions != 0 || fixture.session.preparation != nil || vaultReads.Load() != before {
			t.Fatal("absent candidate entered private preparation", waiting, e)
		}
		if blocked, e := h.durable.CredentialDeliveryBlocked(ctx, p); e != nil || blocked {
			t.Fatal("absent candidate created durable barrier", e)
		}
		probe.available = true
		ready, e := h.CredentialStatus(ctx, p, ref)
		if e != nil || ready.State != "ready" || fixture.admissions != 1 || fixture.session.preparation == nil {
			t.Fatal("fresh candidate did not advance same preparation", ready, e)
		}
		return
	}
	beforePreflightReads := vaultReads.Load()
	status, e := h.CredentialStatus(ctx, p, ref)
	if mode == "inspectionChallenge" {
		if e != nil || status.Stage != "challenge" || status.AttentionCode != "privateInspectionChallenge" || status.State != "needsNativeAction" || fixture.fills != 0 || fixture.submits != 0 || vaultReads.Load() != beforePreflightReads || len(fixture.session.attempts) != 0 {
			t.Fatal("closed challenge diagnostic lost or caused input", status, e)
		}
		return
	}
	expectedStatus := "ready"
	if mode == "unavailable" || strings.HasPrefix(mode, "preflightRetire") {
		expectedStatus = "needsNativeAction"
	}
	if e != nil || status.State != expectedStatus {
		t.Fatal(status, e)
	}
	if (mode == "unavailable" || strings.HasPrefix(mode, "preflightRetire")) && status.AttentionCode != "privateBrowserAdmission" || mode != "unavailable" && !strings.HasPrefix(mode, "preflightRetire") && status.AttentionCode != "" {
		t.Fatal("private preflight diagnostic is not a closed failing boundary")
	}
	if fixture.fills != 0 || fixture.submits != 0 || vaultReads.Load() != beforePreflightReads || len(fixture.session.attempts) != 0 {
		t.Fatal("status preflight consumed credential bytes or created an input attempt")
	}
	if strings.HasPrefix(mode, "preflightRetire") {
		exerciseCredentialPreflightRetirement(t, h, ctx, p, ref, input, fixture, mode)
		return
	}
	if mode != "unavailable" && (status.Stage != "username" || fixture.session.protected == nil) {
		t.Fatal("status did not privately qualify form shape")
	}
	if mode != "unavailable" {
		repeated, e := h.CredentialStatus(ctx, p, ref)
		if e != nil || repeated != status || fixture.admissions != 1 || fixture.freshness != 1 || fixture.fills != 0 || fixture.submits != 0 || vaultReads.Load() != beforePreflightReads || len(fixture.session.attempts) != 0 {
			t.Fatal("repeated preflight replayed admission or consumed values", e)
		}
	}
	if hook.exercise != nil {
		hook.exercise(t, h, ctx, p, ref, input, fixture, vaultReads)
		return
	}
	if strings.HasPrefix(mode, "scope") {
		exerciseCredentialScopePolicy(t, h, ctx, p, ref, input, fixture, mode, vaultReads)
		return
	}
	other := p
	other.ClientID = "foreign"
	if _, e = h.CredentialStatus(auth.WithPrincipal(ctx, other), other, ref); e == nil {
		t.Fatal("foreign opaque reference used")
	}
	if mode == "closeDuringFill" {
		sent := make(chan struct{})
		fixture.waitForClose = sent
		result := make(chan gateway.CredentialResult, 1)
		go func() { r, _ := h.CredentialApply(ctx, p, ref); result <- r }()
		select {
		case <-sent:
		case <-time.After(15 * time.Second):
			t.Fatal("private dispatch did not start")
		}
		if e = h.Runtime.Close(ctx, session.SessionID); e != nil {
			t.Fatal(e)
		}
		select {
		case stopped := <-result:
			if stopped.State != "unknown" || stopped.DispatchState != "unknown" {
				t.Fatal("session close erased possible dispatch", stopped)
			}
		case <-time.After(time.Second):
			t.Fatal("owned session close did not cancel active private transport")
		}
		if blocked, e := h.durable.CredentialDeliveryBlocked(ctx, p); e != nil || !blocked {
			t.Fatal("session close lost durable unknown")
		}
		return
	}
	if mode == "sessionClose" || mode == "sessionRecover" {
		flow := h.credentials.pending[ref.PreparationID]
		if e = h.Runtime.Close(ctx, session.SessionID); e != nil {
			t.Fatal(e)
		}
		if flow.done.Err() == nil {
			t.Fatal("owned session closure did not inhibit private capability")
		}
		if _, e = h.CredentialApply(ctx, p, ref); e == nil {
			t.Fatal("closed session reused private capability")
		}
		if mode == "sessionRecover" {
			recovery, e := h.Runtime.Open(ctx, "metadata recovery")
			if e != nil {
				t.Fatal(e)
			}
			recoveryCtx := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: recovery.SessionID, GrantID: "fresh-recovery", Purpose: "verified normal quit"})
			surface := model.Surface{Kind: "native", BundleID: "com.google.Chrome", ProcessID: 86777, ProcessStartToken: "1791601240:370749"}
			flow.authority.Evidence.ChromeParent.PID = surface.ProcessID
			flow.authority.Evidence.ChromeParent.StartToken = surface.ProcessStartToken
			calls := 0
			guard := func(c context.Context) error {
				if h.Runtime.CheckSession(c, p, recovery.SessionID) != nil {
					return errPrivateCredential
				}
				return credentialOriginalProcessGone(surface, func(int) (sessionpkg.ProcessIdentity, bool, error) { return sessionpkg.ProcessIdentity{}, false, nil })
			}
			if _, e = h.vaultExposure.AcquireExposureContext(recoveryCtx); !errors.Is(e, vault.ErrDeliveryProtected) {
				t.Fatal("expected original retired barrier")
			}

			wrong := surface
			wrong.ProcessStartToken = "wrong-birth"
			if h.withCredentialRecoveryProtection(recoveryCtx, p, ref.PreparationID, wrong, guard, func(context.Context) error { t.Fatal("wrong birth reached ledger"); return nil }) == nil {
				t.Fatal("wrong birth retired private lease")
			}
			alive := func(c context.Context) error {
				return credentialOriginalProcessGone(surface, func(int) (sessionpkg.ProcessIdentity, bool, error) {
					return sessionpkg.ProcessIdentity{PID: surface.ProcessID, StartToken: surface.ProcessStartToken}, true, nil
				})
			}
			if h.withCredentialRecoveryProtection(recoveryCtx, p, ref.PreparationID, surface, alive, func(context.Context) error { t.Fatal("alive process reached ledger"); return nil }) == nil {
				t.Fatal("alive original retired lease")
			}
			e = h.withCredentialRecoveryProtection(recoveryCtx, p, ref.PreparationID, surface, guard, func(recoveryHeld context.Context) error {
				return h.durable.WithCredentialDeliveryComponents(recoveryHeld, p, func(held context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
					calls++
					prep, _, e := h.durable.LoadCredentialRecovery(held, p, ref.PreparationID)
					if e != nil || prep.ProtectionState != "held" {
						t.Fatal("real durable recovery provenance unavailable", e)
					}
					if _, e = h.vaultExposure.AcquireExposureContext(held); !errors.Is(e, vault.ErrDeliveryProtected) {
						t.Fatal("exposure released before retirement")
					}
					clean, stop, e := data.WithCredentialRetirementAuthority(held, prep, nil, surface.ProcessStartToken, guard)
					if e != nil {
						return e
					}
					defer stop()
					old := prep
					old.ProtectionState = "closed"
					old.Revision++
					bound, revoke, e := data.WithCredentialPreparationAuthority(clean, old, guard)
					if e != nil {
						return e
					}
					defer revoke()
					return h.durable.CloseCredentialPreparation(bound, p)
				})
			})
			if e != nil || calls != 1 {
				t.Fatal("exact gone retired-session cleanup blocked", e)
			}
			release, e := h.vaultExposure.AcquireExposureContext(recoveryCtx)
			if e != nil {
				t.Fatal(e)
			}
			release()
		}
		return
	}

	if mode == "restartRecovery" || mode == "restartRecoveryUnknown" {
		fixture.session.authority.Evidence.ChromeParent.StartToken = "1:1"
	}
	verifyRestartRecovery := func() {
		if h.Runtime.Close(ctx, session.SessionID) != nil {
			t.Fatal("original session close failed")
		}
		h.credentials.mu.Lock()
		delete(h.credentials.pending, ref.PreparationID)
		h.credentials.mu.Unlock()
		h.vaultExposure, e = vault.NewGuardedExposureGate(func(context.Context) error { return nil })
		if e != nil {
			t.Fatal(e)
		}
		recovery, e := h.Runtime.Open(ctx, "restart durable recovery")
		if e != nil {
			t.Fatal(e)
		}
		recoveryCtx := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: recovery.SessionID, GrantID: "fresh", Purpose: "verified normal quit"})
		newQuit := model.Surface{Kind: "native", BundleID: "com.google.Chrome", ProcessID: 987654, ProcessStartToken: "2:2"}
		guard := func(c context.Context) error {
			if h.Runtime.CheckSession(c, p, recovery.SessionID) != nil {
				return errPrivateCredential
			}
			return credentialOriginalProcessGone(newQuit, func(int) (sessionpkg.ProcessIdentity, bool, error) { return sessionpkg.ProcessIdentity{}, false, nil })
		}
		foreign := p
		foreign.ClientID = "foreign"
		if h.retireCredentialRecovery(recoveryCtx, foreign, ref.PreparationID, newQuit, guard) == nil {
			t.Fatal("foreign owner recovered durable history")
		}
		e = h.withCredentialRecoveryProtection(recoveryCtx, p, ref.PreparationID, newQuit, guard, func(c context.Context) error {
			return h.retireCredentialRecovery(c, p, ref.PreparationID, newQuit, guard)
		})
		if e != nil {
			t.Fatal("restart mismatch recovery unavailable", e)
		}
		e = h.durable.WithCredentialDeliveryComponents(recoveryCtx, p, func(c context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
			prep, rows, e := h.durable.LoadCredentialRecovery(c, p, ref.PreparationID)
			if e != nil {
				return e
			}
			if prep.ProtectionState != "closed" || len(rows) != len(fixture.session.attempts) {
				t.Fatal("durable retirement absent")
			}
			for _, row := range rows {
				if row.ChromeStartToken != "1:1" || row.DispatchState != "dispatched" && row.DispatchState != "unknown" || row.DispatchState == "dispatched" && row.ProtectionState != "closed" || row.DispatchState == "unknown" && row.ProtectionState != "retired" {
					t.Fatal("original audit identity/outcome changed")
				}
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
		return
	}
	if mode != "unavailable" {

		filled, e := h.CredentialApply(ctx, p, ref)
		if e != nil {
			t.Fatal(e)
		}
		expected := "filled"
		if fixture.unknown {
			expected = "unknown"
		}
		if filled.State != expected || fixture.fills != 1 {
			t.Fatal("fill result", filled, fixture.fills)
		}
		if repeated, e := h.CredentialApply(ctx, p, ref); e != nil || repeated != filled || fixture.fills != 1 {
			t.Fatal("fill replay")
		}
		if mode == "restartRecoveryUnknown" {
			verifyRestartRecovery()
			return
		}
		submitted, e := h.CredentialSubmit(ctx, p, ref)
		if e != nil {
			t.Fatal(e)
		}
		if fixture.unknown {
			fixture.session.expires = time.Now().Add(-time.Second)
			if retry, err := h.CredentialPrepare(ctx, p, input); err == nil && (retry.State != "needsNativeAction" || retry.PreparationID != "" || retry.AttentionCode == "") || h.credentials.pending[prepared.PreparationID] == nil {
				t.Fatal("expiry erased unknown barrier or allowed new delivery")
			}
			if fixture.submits != 0 || submitted.State != "unknown" {
				t.Fatal("unknown fill submitted")
			}
		} else {
			if fixture.submits != 1 || submitted.State != "submitted" {
				t.Fatal("submit unavailable", submitted, fixture.submits)
			}
			if repeated, e := h.CredentialSubmit(ctx, p, ref); e != nil || repeated != submitted || fixture.submits != 1 {
				t.Fatal("submit replay")
			}
			if mode == "restartRecovery" {
				verifyRestartRecovery()
				return
			}

			if strings.HasPrefix(mode, "manualRetirement") {
				e = h.durable.WithCredentialDeliveryComponents(auth.WithConsentBinding(ctx, fixture.session.consent), p, func(held context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
					prep, rows, e := h.durable.LoadCredentialRecovery(held, p, ref.PreparationID)
					if e != nil || len(rows) != 2 {
						t.Fatal("real owned history missing", e)
					}
					before := append([]data.CredentialDeliveryRecord(nil), rows...)
					currentLease, e := h.authorizeConsentOperation(consent.RequireReusableGrant(held), p, model.Surface{Kind: "web", Origin: prep.Origin}, true, consent.Control)
					if e != nil {
						return e
					}
					defer currentLease.Release()
					cb, _ := auth.ConsentBindingFromContext(currentLease.Context)
					admission := &manualCleanupAdmission{host: h, actor: p, sessionID: cb.SessionID, surface: model.Surface{Kind: "web", Origin: prep.Origin}, binding: cb, lease: currentLease}
					held = currentLease.Context
					var stop func()
					held, stop = admission.cleanupContext(held)
					defer stop()
					t.Log("real consent admitted; entering generated cleanup lifecycle with retained privacy callback")

					calls := 0
					guard := func(c context.Context) error {
						// Same admission check runs directly and from the
						// retained privacy proof callback in the real handoff.
						if e := admission.check(c); e != nil {
							return e
						}
						if e := admission.check(c); e != nil {
							return e
						}
						calls++
						if mode == "manualRetirementRevoked" && calls >= 2 {
							return errPrivateCredential
						}
						if _, e := h.vaultExposure.AcquireExposureContext(c); !errors.Is(e, vault.ErrDeliveryProtected) {
							t.Fatal("manual retirement released exposure")
						}
						return c.Err()
					}
					if mode == "manualRetirementPartial" {
						writes := 0
						e = retireManualCredentialInputs(held, p, prep, rows, guard, func(c context.Context, actor auth.Principal) error {
							writes++
							if writes == 2 {
								return errPrivateCredential
							}
							return h.durable.FinishCredentialDelivery(c, actor)
						})
					} else {
						e = h.retireManualCredentialInputs(held, p, prep, rows, guard)
					}
					if (e == nil) != (mode == "manualRetirement") {
						t.Fatal("guard rejection ignored", e)
					}
					afterParent, after, loadErr := h.durable.LoadCredentialRecovery(held, p, ref.PreparationID)
					if loadErr != nil || afterParent != prep || len(after) != len(before) {
						t.Fatal("held parent changed", loadErr)
					}
					for i, row := range after {
						expected := before[i]
						if mode == "manualRetirement" || mode == "manualRetirementPartial" && i == 0 {
							expected.ProtectionState = "closed"
							expected.Revision++
							expected.UpdatedAt = row.UpdatedAt
						}
						if !reflect.DeepEqual(row, expected) {
							t.Fatal("original outcome/provenance changed")
						}
					}
					if mode == "manualRetirement" || mode == "manualRetirementPartial" {
						if e = h.retireManualCredentialInputs(held, p, afterParent, after, guard); e != nil {
							t.Fatal("closed known retry failed", e)
						}
					}
					return nil
				})
				if e != nil || fixture.fills != 1 || fixture.submits != 1 {
					t.Fatal("manual cleanup replayed input", e)
				}
				return
			}
			originalAuthority, originalBinding := fixture.session.authority, fixture.session.binding
			if mode == "expiredChallenge" {
				fixture.session.expires = time.Now().Add(-time.Second)
			}
			advanced, e := h.CredentialStatus(ctx, p, ref)

			if mode == "postPending" || mode == "postRejected" {
				want := "submitted"
				attention := "postSubmitPending"
				if mode == "postRejected" {
					want = "needsNativeAction"
					attention = "loginRejected"
				}
				if e != nil || advanced.State != want || advanced.Stage != fixture.postStage || advanced.AttentionCode != attention || fixture.session.binding != originalBinding || !reflect.DeepEqual(fixture.session.authority, originalAuthority) {
					t.Fatal("post-submit metadata altered input authority", advanced, e)
				}
				h.CredentialStatus(ctx, p, ref)
				h.CredentialApply(ctx, p, ref)
				h.CredentialSubmit(ctx, p, ref)
				if fixture.fills != 1 || fixture.submits != 1 || len(fixture.session.attempts) != 2 {
					t.Fatal("read-only status replayed input")
				}
				if blocked, e := h.durable.CredentialDeliveryBlocked(ctx, p); e != nil || !blocked {
					t.Fatal("status cleared protection", e)
				}
				return
			}
			if mode == "challenge" || mode == "expiredChallenge" {
				if e != nil || advanced.State != "needsNativeAction" || advanced.Stage != "challenge" || fixture.fills != 1 || fixture.submits != 1 {
					t.Fatal("challenge was not a nonsecret human handoff", advanced, e)
				}
				if ignored, e := h.CredentialApply(ctx, p, ref); e != nil || ignored.State != "needsNativeAction" || fixture.fills != 1 {
					t.Fatal("challenge autofilled")
				}
				if ignored, e := h.CredentialSubmit(ctx, p, ref); e != nil || ignored.State != "needsNativeAction" || fixture.submits != 1 {
					t.Fatal("challenge submitted")
				}
				if fixture.session.binding != originalBinding || fixture.session.authority.Document != originalAuthority.Document || fixture.session.authority.Lease != originalAuthority.Lease {
					t.Fatal("challenge adopted new input authority")
				}
				if mode == "expiredChallenge" {
					if fixture.session.selection == nil {
						t.Fatal("metadata-only status discarded retained selection provenance")
					}
					if blocked, e := h.durable.CredentialDeliveryBlocked(ctx, p); e != nil || !blocked {
						t.Fatal("expired challenge cleared barrier")
					}
					return
				}
				fixture.challenge = false
				advanced, e = h.CredentialStatus(ctx, p, ref)
			}
			if mode == "privacyCandidate" {
				if e != nil || advanced.State != "needsNativeAction" || fixture.privacyCalls != 1 || fixture.session.dom != nil {
					t.Fatal("zero/untrusted proof activated DOM privacy", advanced, e)
				}
				if blocked, e := h.durable.CredentialDeliveryBlocked(ctx, p); e != nil || !blocked {
					t.Fatal("candidate cleared barrier")
				}
				return
			}

			if e != nil || advanced.State != "ready" || advanced.Stage != "password" {
				t.Fatal("private next document unavailable", advanced, e)
			}
			filled, e = h.CredentialApply(ctx, p, ref)
			if e != nil || filled.State != "filled" || fixture.fills != 2 {
				t.Fatal("password step unavailable", filled, e)
			}
			submitted, e = h.CredentialSubmit(ctx, p, ref)
			if e != nil || submitted.State != "submitted" || fixture.submits != 2 {
				t.Fatal("password submit unavailable", submitted, e)
			}
		}
		if mode == "known" {
			exerciseCredentialDOMPolicy(t, h, ctx, p, ref)
		}
		if blocked, e := h.durable.CredentialDeliveryBlocked(ctx, p); e != nil || !blocked {
			t.Fatal("known/unknown dispatch cleared privacy barrier", e)
		}
		return
	}
	applied, e := h.CredentialApply(ctx, p, ref)
	if e != nil || applied.State != "needsNativeAction" {
		t.Fatal(applied, e)
	}
	if blocked, e := h.durable.CredentialDeliveryBlocked(ctx, p); e != nil || !blocked {
		t.Fatal("failed private inspector lost durable pre-probe protection", e)
	}
	again, e := h.CredentialApply(ctx, p, ref)
	if e != nil || again != applied {
		t.Fatal("failed inspector replayed", again, e)
	}
	if _, e = h.AuthorizeOperation(auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: session.SessionID, Purpose: "observe"}), p, input.Surface, false, consent.Observe); e == nil {
		t.Fatal("ordinary exposure bypassed durable protection")
	}
	raw, _ := json.Marshal([]gateway.CredentialResult{prepared, status, applied, again})
	for _, secret := range []string{"canary", meta.Reference.ID, meta.Revision, "native-session"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("private metadata/value escaped")
		}
	}
}

// Availability is routing metadata, never a private form probe or input.
type credentialCandidateFixture struct {
	credentialBrowser
	available bool
}

func (f *credentialCandidateFixture) CredentialCandidateAvailable(context.Context, auth.Principal, model.Surface) error {
	if !f.available {
		return errPrivateCredential
	}
	return nil
}

func TestManualRetirementRealHostDurableParentHeld(t *testing.T) {
	for _, mode := range []string{"manualRetirement", "manualRetirementRevoked", "manualRetirementPartial"} {
		t.Run(mode, func(t *testing.T) { credentialHostFixtureFlow(t, mode) })
	}
}

func TestCredentialInspectionChallengePreservesClosedStage(t *testing.T) {
	credentialHostFixtureFlow(t, "inspectionChallenge")
}

func TestManualCleanupAdmittedLeaseRevocationExpiryAndPersistentChecks(t *testing.T) {
	credentialHostFixtureFlow(t, "manualCleanupLeaseChecks", credentialHostFixtureHooks{exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, in gateway.CredentialPrepareInput, f *credentialBrowserFixture, _ *atomic.Int64) {
		persistent := auth.WithConsentBinding(ctx, f.session.consent)
		current, e := h.authorizeConsentOperation(consent.RequireReusableGrant(persistent), p, in.Surface, true, consent.Control)
		if e != nil {
			t.Fatal(e)
		}
		defer current.Release()
		cb, _ := auth.ConsentBindingFromContext(current.Context)
		a := &manualCleanupAdmission{host: h, actor: p, sessionID: cb.SessionID, surface: in.Surface, binding: cb, lease: current}
		scoped, stop := a.cleanupContext(current.Context)
		defer stop()
		originalInvoke := h.consent.options.Invoke
		defer func() { h.consent.options.Invoke = originalInvoke }()
		var reads atomic.Int64
		h.consent.options.Invoke = func(c context.Context, actor auth.Principal, r exec.ComponentRequest) (any, error) {
			reads.Add(1)
			return originalInvoke(c, actor, r)
		}
		if e = a.check(scoped); e != nil {
			t.Fatal("valid scoped admission refused", e)
		}
		if reads.Load() != 0 {
			t.Fatal("scoped guard recursively read consent")
		}
		if e = a.check(persistent); e != nil || reads.Load() == 0 {
			t.Fatal("persistent unmarked guard skipped ordinary consent lookup", e)
		}
		foreign := p
		foreign.ClientID = "foreign"
		if a.check(auth.WithPrincipal(scoped, foreign)) == nil {
			t.Fatal("foreign actor borrowed cleanup admission")
		}
		wrong := cb
		wrong.GrantID = "foreign"
		if a.check(auth.WithConsentBinding(scoped, wrong)) == nil {
			t.Fatal("foreign binding borrowed cleanup admission")
		}
		stop()
		if a.check(scoped) == nil {
			t.Fatal("stale marked context revived after cleanup")
		}
		scoped, stop = a.cleanupContext(current.Context)
		defer stop()
		expiring, expire := context.WithTimeout(persistent, 500*time.Millisecond)
		defer expire()
		expiringLease, e := h.authorizeConsentOperation(consent.RequireReusableGrant(expiring), p, in.Surface, true, consent.Control)
		if e != nil {
			t.Fatal("expiring actual consent admission", e)
		}
		defer expiringLease.Release()
		expiredAdmission := &manualCleanupAdmission{host: h, actor: p, sessionID: cb.SessionID, surface: in.Surface, binding: cb, lease: expiringLease}
		// Caller stays live: the retained real consent lease's own deadline must deny.
		expiryScoped, stopExpiry := expiredAdmission.cleanupContext(persistent)
		defer stopExpiry()
		<-expiringLease.Context.Done()
		if expiredAdmission.check(expiryScoped) == nil {
			t.Fatal("expired admitted lease retained cleanup authority")
		}
		blocked, release := make(chan struct{}), make(chan struct{})
		h.consent.options.Invoke = func(c context.Context, actor auth.Principal, r exec.ComponentRequest) (any, error) {
			close(blocked)
			<-release
			return originalInvoke(c, actor, r)
		}
		human, e := auth.WithNativeHuman(ctx)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(map[string]any{"grantID": cb.GrantID})
		revoked := make(chan error, 1)
		go func() { _, e := h.consent.NativeRPC(human, "revoke", raw); revoked <- e }()
		select {
		case <-blocked:
		case <-time.After(2 * time.Second):
			t.Fatal("real revoke did not reach its persistence boundary")
		}
		// Restore before the revoke's subsequent generated write; only its first
		// lookup is held, proving cancellation happens before database persistence.
		h.consent.options.Invoke = originalInvoke
		if current.Context.Err() == nil || a.check(scoped) == nil {
			t.Error("real revocation did not synchronously inhibit admitted cleanup")
		}
		close(release)
		select {
		case e := <-revoked:
			if e != nil {
				t.Fatal(e)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("revoke failed to finish after releasing fixture barrier")
		}
		if a.check(persistent) == nil {
			t.Fatal("persistent later guard bypassed revoked consent")
		}
		t.Log("real admitted lease: zero nested lookup during scoped cleanup, ordinary lookup after scope, foreign/stale/expired refusal, synchronous revoke before persistence")
	}})
}

func TestCredentialAdvanceDiagnosticSurvivesVaultResolverCollapse(t *testing.T) {
	credentialHostFixtureFlow(t, "known", credentialHostFixtureHooks{exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
		if r, e := h.CredentialApply(ctx, p, ref); e != nil || r.State != "filled" {
			t.Fatal(r, e)
		}
		if r, e := h.CredentialSubmit(ctx, p, ref); e != nil || r.State != "submitted" {
			t.Fatal(r, e)
		}
		f.postStage = "controlDiagnostic"
		before := append([]data.CredentialDeliveryRecord(nil), f.session.attempts...)
		r, e := h.CredentialStatus(ctx, p, ref)
		if e != nil || r.AttentionCode != "postSubmitControlAuthorityUnavailable" || r.State != "needsNativeAction" || r.DispatchState != "dispatched" {
			t.Fatal("phase collapsed", r, e)
		}
		if !reflect.DeepEqual(before, f.session.attempts) || f.fills != 1 || f.submits != 1 {
			t.Fatal("diagnostic replayed input or changed receipt")
		}
		raw, _ := json.Marshal(r)
		if bytes.Contains(raw, []byte("CANARY")) {
			t.Fatal("raw private error escaped")
		}
	}})
}
