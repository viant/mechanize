package chrome

import (
	"context"
	"errors"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"strings"
	"testing"
)

func TestAutomaticPrivacySourceRetirementRevokesBNotItsRedactor(t *testing.T) {
	f, c, ctx := publicReadFixture(t)
	b := f.g.broker
	b.mu.Lock()
	c.privacySourceRetirementVersion = 1
	c.credentialPublicReadVersion = 2
	c.documents = []Document{{Identity: Identity{ProfileChannel: "p1", BrowserInstance: "b1", TabID: 7, DocumentID: "doc1", Generation: 1}, Origin: "https://fixture.test"}}
	source := c.documents[0]
	source.DocumentID = "old-login"
	sourceAuthority := ControlAuthority{Document: source, Lease: Lease{ID: "old-lease", Generation: 3}}
	privacy := &credentialPrivacyState{gateway: f.g, channel: c, conn: c.conn, source: sourceAuthority, identity: c.documents[0].Identity, authority: ControlAuthority{Document: c.documents[0]}, active: true, published: true, submitID: strings.Repeat("b", 64)}
	c.privacy = privacy
	scope := CredentialProtectionScope{PreparationID: strings.Repeat("a", 64), Identity: source.Identity, Origin: source.Origin, ChromeStartToken: c.processEvidence.ChromeParent.StartToken}
	b.mu.Unlock()
	proof := CredentialPrivacyProof{state: privacy}
	if _, ok := proof.Authority(); !ok {
		t.Fatal("fixture old privacy not valid")
	}
	if e := f.g.RetireAbsentCredentialScope(ctx, f.p, scope); e != nil {
		t.Fatal(e)
	}
	request := f.lastScope.Load().(credentialScopeRequest)
	if request.Mode != "retire" || request.SourceIdentity != source.Identity || request.RetirementProof == nil || len(request.RetirementProof.Candidates) != 1 || request.RetirementProof.Candidates[0].SubmitAttemptID != privacy.submitID || request.RetirementProof.Candidates[0].ControlLease != sourceAuthority.Lease {
		t.Fatal("A provenance not bound to confirmed submit lease")
	}
	if _, ok := proof.Authority(); ok {
		t.Fatal("old B authority survived retirement")
	}
	if _, e := f.g.Observe(ctx, f.p, readTarget().Surface); e == nil {
		t.Fatal("B raw DOM survived retirement")
	}
	if !f.g.NeedsVerifiedPublicRead(ctx, f.p, readTarget().Surface) {
		t.Fatal("B not required to freshly classify")
	}
	f.publicReadMode.Store("private")
	if _, e := f.g.WithVerifiedCredentialPublicRead(ctx, f.p, readTarget().Surface); e == nil {
		t.Fatal("protected B accepted as public")
	}
	f.publicReadMode.Store("ready")
	fresh, e := f.g.WithVerifiedCredentialPublicRead(ctx, f.p, readTarget().Surface)
	if e != nil {
		t.Fatal(e)
	}
	if e = WriteFrame(f.workerConn, map[string]any{"type": "credentialPrivacyResult", "requestId": "old-retired", "PRIVATE-CANARY": "never-public"}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.g.Observe(fresh, f.p, readTarget().Surface); e != nil {
		t.Fatal("fresh qualified read", e)
	}
	b.mu.Lock()
	c.credentialCandidates = []credentialCandidate{{Identity: Identity{ProfileChannel: "p1", BrowserInstance: "b1", TabID: 7, DocumentID: "doc1", Generation: 1}, Origin: scope.Origin}}
	b.mu.Unlock()
	if e = f.g.CredentialCandidateAvailable(ctx, f.p, readTarget().Surface); e != nil {
		t.Fatal("fresh private candidate remains blocked", e)
	}
	if f.mutations.Load() != 0 {
		t.Fatal("retirement performed input")
	}
}

func TestRetirementProofFromCompleteSnapshotSurvivesBrokerRestart(t *testing.T) {
	f, c, ctx := publicReadFixture(t)
	b := f.g.broker
	b.mu.Lock()
	c.privacy = nil
	c.privacySourceRetirementVersion = 1
	b.mu.Unlock()
	ctx, e := data.WithScope(ctx, data.Scope{Namespace: f.p.Namespace})
	if e != nil {
		t.Fatal(e)
	}
	source := data.CredentialProtectionScopeRecord{Namespace: f.p.Namespace, ClientID: "controller:" + strings.Repeat("a", 64), PreparationID: strings.Repeat("b", 64), Origin: "https://fixture.test", ProfileChannel: "p1", BrowserInstance: "b1", TabID: 7, DocumentID: "old-login", DocumentGeneration: 1, ChromeStartToken: c.processEvidence.ChromeParent.StartToken, BrokerEpoch: "original", ChannelEpoch: "original", ScopeHash: strings.Repeat("c", 64), LoginRouteSHA256: strings.Repeat("d", 64), CreatedAt: "2026-10-13T00:00:00Z"}
	guard := func(c context.Context) error { return c.Err() }
	sealed, stop, e := data.WithCredentialSourceLifecycleAuthority(ctx, source, guard)
	if e != nil {
		t.Fatal(e)
	}
	defer stop()
	prep := data.CredentialPreparationRecord{Namespace: source.Namespace, ClientID: source.ClientID, PreparationID: source.PreparationID, SessionID: "old-session", GrantID: "old-grant", PurposeHash: data.CredentialDeliveryPurposeHash("old"), Origin: source.Origin, SelectedRevision: strings.Repeat("d", 64), ProtectionState: "held", Revision: 1, CreatedAt: source.CreatedAt}
	row := data.CredentialDeliveryRecord{Namespace: prep.Namespace, ClientID: prep.ClientID, SessionID: prep.SessionID, SelectionID: prep.PreparationID, GrantID: prep.GrantID, PurposeHash: prep.PurposeHash, SelectedRevision: prep.SelectedRevision, Origin: prep.Origin, AttemptID: strings.Repeat("e", 64), ProfileChannel: source.ProfileChannel, BrowserInstance: source.BrowserInstance, TabID: source.TabID, DocumentID: source.DocumentID, DocumentGeneration: 1, ChromeStartToken: source.ChromeStartToken, RendererLeaseID: "old-lease", RendererLeaseGeneration: 3, DispatchState: "dispatched", ProtectionState: "held", Revision: 2, CreatedAt: source.CreatedAt, UpdatedAt: source.CreatedAt}
	unknown := row
	unknown.AttemptID = strings.Repeat("f", 64)
	unknown.DispatchState = "unknown"
	unknown.Revision = 1
	clean, release, e := data.WithCredentialSourceAbsenceAuthority(sealed, prep, []data.CredentialDeliveryRecord{row, unknown}, []data.CredentialProtectionScopeRecord{source}, guard)
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	scope := CredentialProtectionScope{PreparationID: source.PreparationID, Identity: Identity{ProfileChannel: source.ProfileChannel, BrowserInstance: source.BrowserInstance, TabID: 7, DocumentID: source.DocumentID, Generation: 1}, Origin: source.Origin, ChromeStartToken: source.ChromeStartToken}
	if e = f.g.RetireAbsentCredentialScope(clean, f.p, scope); e != nil {
		t.Fatal(e)
	}
	q := f.lastScope.Load().(credentialScopeRequest)
	if q.RetirementProof == nil || len(q.RetirementProof.Candidates) != 1 || q.RetirementProof.Candidates[0].SubmitAttemptID != row.AttemptID {
		t.Fatal("restart lost original known outcome, or converted UNKNOWN into submit proof")
	}
	b.mu.Lock()
	c.privacySourceRetirementVersion = 0
	b.mu.Unlock()
	scope = WithCredentialRetirementSnapshot(scope, []data.CredentialDeliveryRecord{row, unknown})
	if e = f.g.VerifyCredentialScopeAbsent(clean, f.p, scope); CredentialProtectionFailureReason(e) != "scopeUnsupported" {
		t.Fatal("old worker did not refuse before CAS", e)
	}
	if e = f.g.RetireAbsentCredentialScope(clean, f.p, scope); CredentialProtectionFailureReason(e) != "scopeUnsupported" {
		t.Fatal("old worker silently accepted unsupported retirement", e)
	}
	release()
	if len(data.CredentialSourceCleanupAttempts(clean)) != 0 {
		t.Fatal("released cleanup proof still exposes rows")
	}
}

func TestCredentialSourceIdleIgnoresDormantOwnersButDeniesActualWork(t *testing.T) {
	f, c, ctx := publicReadFixture(t)
	b := f.g.broker
	c.privateFlow = &credentialFlow{}
	c.controllerSessions = map[string]*ControllerSession{"old": {identity: ControllerIdentity{Principal: f.p}}}
	if e := f.g.VerifyCredentialSourceIdle(ctx, f.p); e != nil {
		t.Fatal("dormant owner considered input", e)
	}
	for _, kind := range []string{"lane", "unknown", "private", "inspection", "pending", "lifecycle", "proofRPC"} {
		t.Run(kind, func(t *testing.T) {
			b.mu.Lock()
			switch kind {
			case "lane":
				b.lane <- struct{}{}
			case "unknown":
				c.unknown["original"] = true
			case "private":
				c.privateCredential = &credentialDeliveryPending{}
			case "inspection":
				c.privateInspection = &credentialAdmissionPending{}
			case "pending":
				c.pending["original"] = &pending{}
			case "lifecycle":
				c.lifecycleInhibited = true
			case "proofRPC":
				c.protectionPending = &credentialScopePending{}
			}
			b.mu.Unlock()
			if e := f.g.VerifyCredentialSourceIdle(ctx, f.p); !errors.Is(e, ErrCredentialSourceInputBusy) {
				t.Fatal("actual work not rejected", e)
			}
			b.mu.Lock()
			switch kind {
			case "lane":
				<-b.lane
			case "unknown":
				delete(c.unknown, "original")
			case "private":
				c.privateCredential = nil
			case "inspection":
				c.privateInspection = nil
			case "pending":
				delete(c.pending, "original")
			case "lifecycle":
				c.lifecycleInhibited = false
			case "proofRPC":
				c.protectionPending = nil
			}
			b.mu.Unlock()
		})
	}
}

func TestOwnedSourceProofRPCIsIdleOnlyUnderExactCurrentProcessPin(t *testing.T) {
	f, c, ctx := publicReadFixture(t)
	b := f.g.broker
	b.mu.Lock()
	scope := CredentialProtectionScope{PreparationID: strings.Repeat("a", 64), Identity: Identity{ProfileChannel: "p1", BrowserInstance: "b1", TabID: 7, DocumentID: "original-login", Generation: 1}, Origin: "https://fixture.test", ChromeStartToken: c.processEvidence.ChromeParent.StartToken}
	binding, _ := auth.ConsentBindingFromContext(ctx)
	pin := &credentialScopeProcessPin{broker: b, owner: f.p.Namespace, client: f.p.ClientID, binding: binding, sources: []CredentialProtectionScope{scope}, channels: map[*channel]credentialScopeChannelPin{c: {conn: c.conn, evidence: c.processEvidence, brokerEpoch: b.epoch, channelEpoch: c.epoch, scopeHash: c.scopeHash}}}
	c.protectionPending = &credentialScopePending{conn: c.conn, request: credentialScopeRequest{Mode: "absent", PreparationID: scope.PreparationID, SourceIdentity: scope.Identity, SourceOrigin: scope.Origin, BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash}}
	b.mu.Unlock()
	pinned := context.WithValue(ctx, credentialScopeProcessKey{}, pin)
	if e := f.g.VerifyCredentialSourceIdle(pinned, f.p); e != nil {
		t.Fatal("owned proof RPC counted as input", e)
	}
	for _, kind := range []string{"client", "consent", "epoch", "source", "mode"} {
		t.Run(kind, func(t *testing.T) {
			b.mu.Lock()
			old := c.protectionPending.request
			originalEpoch := c.epoch
			b.mu.Unlock()
			testCtx := pinned
			switch kind {
			case "client":
				p := f.p
				p.ClientID = "other"
				testCtx = auth.WithPrincipal(pinned, p)
			case "consent":
				changed := binding
				changed.GrantID = "other"
				testCtx = auth.WithConsentBinding(pinned, changed)
			case "epoch":
				b.mu.Lock()
				c.epoch = "changed"
				b.mu.Unlock()
			case "source":
				b.mu.Lock()
				c.protectionPending.request.SourceIdentity.DocumentID = "other"
				b.mu.Unlock()
			case "mode":
				b.mu.Lock()
				c.protectionPending.request.Mode = "capture"
				b.mu.Unlock()
			}
			if e := f.g.VerifyCredentialSourceIdle(testCtx, f.p); e == nil {
				t.Fatal("stale/foreign process pin ignored live RPC", kind)
			}
			b.mu.Lock()
			c.protectionPending.request = old
			c.epoch = originalEpoch
			b.mu.Unlock()
		})
	}
}
