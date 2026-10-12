package chromeattemptbindingcreate_test

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/datly/standalone"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/beginattempt"
	create "github.com/viant/mechanize/data/chromeattemptbindingcreate"
	page "github.com/viant/mechanize/data/chromeattemptbindingpage"
	snapshot "github.com/viant/mechanize/data/chromeattemptbindingsnapshot"
	"github.com/viant/mechanize/data/commitoutcome"
	datahost "github.com/viant/mechanize/data/host"
	"github.com/viant/mechanize/internal/datlytest"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"github.com/viant/xdatly/handler"
)

type reconnectGraphFixture struct {
	t                       *testing.T
	ctx                     context.Context
	p                       auth.Principal
	server, fixture, reader *standalone.Server
	plan                    *model.Plan
	planJSON, planHash      string
	serial                  int
}

func newReconnectGraphFixture(t *testing.T) *reconnectGraphFixture {
	t.Helper()
	p, e := auth.NewPrincipal("fixture", "", "reconnect-coverage", []string{"desktop:control"})
	if e != nil {
		t.Fatal(e)
	}
	p.ClientID = "client-a"
	ctx := auth.WithPrincipal(context.Background(), p)
	scope := data.Scope{Namespace: p.Namespace, LeaseEpoch: 1}
	ctx, e = data.WithScope(ctx, scope)
	if e != nil {
		t.Fatal(e)
	}
	storage := t.TempDir()
	cfg, e := data.Provision(ctx, storage, scope)
	if e != nil {
		t.Fatal(e)
	}
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	server, e := datahost.Open(ctx, root, storage, scope)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { server.Shutdown(context.Background()) })
	reader, e := datahost.Open(ctx, root, storage, scope)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { reader.Shutdown(context.Background()) })
	fixtures, e := datlytest.Open(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { fixtures.Shutdown(context.Background()) })
	plan, e := script.Compile(`web.tab(origin:"https://fixture.test").getById("save",exact:true).click()`)
	if e != nil {
		t.Fatal(e)
	}
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"case": {Kind: model.StringValue, String: "fixture"}}
	payload, _ := json.Marshal(map[string]any{"plan": plan})
	planJSON := string(payload)
	planHash := data.ChromeAttemptRawDigest(planJSON)
	e = datlytest.Apply(ctx, fixtures, datlytest.Input{Namespace: p.Namespace, Mode: "graph", Graph: &datlytest.Graph{Plan: &datlytest.Plan{Namespace: p.Namespace, ID: "plan", ObjectiveID: "objective", ContentHash: planHash, ContentJSON: planJSON, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}}})
	if e != nil {
		t.Fatal(e)
	}
	return &reconnectGraphFixture{t: t, ctx: ctx, p: p, server: server, fixture: fixtures, reader: reader, plan: plan, planJSON: planJSON, planHash: planHash}
}
func reconnectInvoke(ctx context.Context, s *standalone.Server, pkg, name, method string, input any) (any, error) {
	return s.InvokeComponent(ctx, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + pkg, Name: name}, Route: spec.RouteRef{Method: method, Path: "/internal/data/" + pkg}}, Input: input})
}
func (f *reconnectGraphFixture) seed(client, epoch, profile, browser, scopeHash, after string) (string, error) {
	f.serial++
	sequence := f.serial
	p := f.p
	p.ClientID = client
	ctx := auth.WithPrincipal(f.ctx, p)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	runID := fmt.Sprintf("run-%d", sequence)
	session, operation := "fixture-session", fmt.Sprintf("operation-%d", sequence)
	attemptID := ""
	bindingID := ""
	for nonce := 0; nonce < 100000; nonce++ {
		attemptID = data.ChromeAttemptRawDigest(fmt.Sprintf("attempt-%d-%d", sequence, nonce))
		bindingID = data.ChromeAttemptBindingID(p.Namespace, p.ClientID, attemptID)
		if bindingID > after {
			break
		}
	}
	if bindingID <= after {
		return "", fmt.Errorf("fixture key allocation failed")
	}
	effectID := data.ChromeRetirementDigest([]string{"effect", attemptID})
	step := f.plan.Steps[0]
	if e := datlytest.Apply(ctx, f.fixture, datlytest.Input{Namespace: p.Namespace, Mode: "graph", Graph: &datlytest.Graph{Run: &datlytest.Run{Namespace: p.Namespace, ID: runID, PlanID: "plan", Status: "running", Revision: 1, SessionID: &session, OperationID: &operation, CreatedAt: now, UpdatedAt: now}}}); e != nil {
		return "", e
	}
	business := fmt.Sprintf(`{"fixture":{"kind":"string","string":"case-%d"}}`, sequence)
	attempt := &beginattempt.Attempt{}
	attempt.SetNamespace(&p.Namespace)
	attempt.SetId(&attemptID)
	attempt.SetRunId(&runID)
	attempt.SetStepId(&step.ID)
	attempt.SetPlanId(stringPointer("plan"))
	attempt.SetLeaseEpoch(intPointer(1))
	attempt.SetState(stringPointer("intent"))
	attempt.SetCreatedAt(&now)
	intent := &beginattempt.Intent{}
	intent.SetNamespace(&p.Namespace)
	intent.SetId(&effectID)
	intent.SetAttemptId(&attemptID)
	intent.SetRunId(&runID)
	intent.SetBusinessKey(&business)
	intent.SetState(stringPointer("intent"))
	intent.SetRevision(intPointer(1))
	attempt.SetIntents([]*beginattempt.Intent{intent})
	event := &beginattempt.Event{}
	event.SetNamespace(&p.Namespace)
	event.SetId(stringPointer(data.ChromeRetirementDigest([]string{"intent-event", attemptID})))
	event.SetRunId(&runID)
	event.SetAttemptId(&attemptID)
	event.SetSequence(intPointer(1))
	event.SetKind(stringPointer("intent"))
	event.SetPayloadJson(stringPointer(`{}`))
	event.SetCreatedAt(&now)
	attempt.SetEvents([]*beginattempt.Event{event})
	run := &beginattempt.Run{}
	run.SetNamespace(&p.Namespace)
	run.SetId(&runID)
	run.SetRevision(intPointer(1))
	run.SetUpdatedAt(&now)
	run.SetAttempts([]*beginattempt.Attempt{attempt})
	begin := &beginattempt.BeginAttemptInput{}
	begin.SetNamespace(p.Namespace)
	begin.SetBeginAttempt([]*beginattempt.Run{run})
	if _, e := reconnectInvoke(ctx, f.server, "beginattempt", "BeginAttempt", "PATCH", begin); e != nil {
		return "", e
	}
	bound := data.ChromeAttemptBindingAuthority{Namespace: p.Namespace, ID: bindingID, ClientID: p.ClientID, RunID: runID, PlanID: "plan", StepID: step.ID, StepIndex: 0, DurableAttemptID: attemptID, EffectID: effectID, BrowserAttemptID: data.ChromeAttemptBrowserIDV2(p.Namespace, p.ClientID, attemptID), ProfileChannel: profile, BrowserInstance: browser, BrokerEpoch: "broker-" + epoch, ChannelEpoch: "channel-" + epoch, ScopeHash: scopeHash, TabID: 7, DocumentID: "document", DocumentGeneration: 1, RendererLeaseID: "lease", RendererLeaseGeneration: 1, FingerprintVersion: 2, FingerprintDigest: strings.Repeat("b", 64), PlanContentDigest: f.planHash, StepDigest: data.ChromeRetirementDigest(step), BusinessKeyDigest: data.ChromeAttemptRawDigest(business), CommittedRunRevision: 2, EndlySessionID: session, EndlyOperationID: operation, CreatedAt: now, GuardProof: "fixture-held-dispatch"}
	committed := data.CommittedStepIntent{Namespace: p.Namespace, ClientID: p.ClientID, RunID: runID, PlanID: "plan", StepID: step.ID, AttemptID: attemptID, EffectID: effectID, LeaseEpoch: 1, RunRevision: 2, SessionID: session, OperationID: operation}
	ctx, revoke, e := data.WithCommittedStepIntent(ctx, p, committed)
	if e != nil {
		return "", e
	}
	defer revoke()
	ctx, e = data.WithChromeAttemptBindingAuthority(ctx, bound)
	if e != nil {
		return "", e
	}
	raw, _ := json.Marshal(bound)
	row := &create.Binding{}
	json.Unmarshal(raw, row)
	markerSet(row)
	input := &create.CreateChromeAttemptBindingInput{}
	input.SetNamespace(p.Namespace)
	input.SetClientID(p.ClientID)
	input.SetAttemptID(attemptID)
	input.SetEffectID(effectID)
	input.SetRunID(runID)
	input.SetPlanID("plan")
	input.SetCreateChromeAttemptBinding([]*create.Binding{row})
	var completion handler.Outcome
	_, e = f.server.InvokeComponent(ctx, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/chromeattemptbindingcreate", Name: "CreateChromeAttemptBinding"}, Route: spec.RouteRef{Method: "POST", Path: "/internal/data/chromeattemptbindingcreate"}}, Input: input, Completion: func(outcome handler.Outcome) { completion = outcome.Clone() }})
	if e != nil {
		return "", e
	}
	if !completion.CommitConfirmed() {
		return "", fmt.Errorf("binding fixture commit unconfirmed")
	}
	return bindingID, nil
}
func (f *reconnectGraphFixture) read(ctx context.Context, guard func(context.Context) error) ([]*page.Binding, error) {
	scoped, e := data.WithChromeReconnectBindingReadAuthority(ctx, data.ChromeReconnectBindingReadScope{ProfileChannel: "profile", BrowserInstance: "browser", ScopeHash: strings.Repeat("a", 64)}, guard)
	if e != nil {
		return nil, e
	}
	value, e := reconnectInvoke(scoped, f.reader, "chromeattemptbindingsnapshot", "SnapshotChromeAttemptBindings", "GET", &snapshot.Input{})
	if e != nil {
		return nil, e
	}
	return value.(*snapshot.Output).Data, nil
}

// Guard invocation at the generated page boundary permits precise concurrent
// arrival fault injection without a production hook or raw database operation.
func inReconnectPageAdmission() bool {
	pcs := make([]uintptr, 32)
	n := runtime.Callers(2, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		if strings.Contains(frame.Function, "chromeattemptbindingpage.(*PageChromeAttemptBindingsInput).Init") {
			return true
		}
		if !more {
			return false
		}
	}
}
func TestDatlyReconnectSnapshotAllClientsEpochsAndConcurrentWriter(t *testing.T) {
	f := newReconnectGraphFixture(t)
	ctx, cancel := context.WithTimeout(f.ctx, 120*time.Second)
	defer cancel()
	f.ctx = ctx
	ids := []string{}
	for i := 0; i < 130; i++ {
		id, e := f.seed(fmt.Sprintf("client-%d", i%3), fmt.Sprint(i), "profile", "browser", strings.Repeat("a", 64), "")
		if e != nil {
			t.Fatalf("seed %d: %v", i, e)
		}
		ids = append(ids, id)
	}
	for i, fields := range [][3]string{{"foreign-profile", "browser", strings.Repeat("a", 64)}, {"profile", "foreign-browser", strings.Repeat("a", 64)}, {"profile", "browser", strings.Repeat("c", 64)}} {
		if _, e := f.seed("foreign", fmt.Sprint(i), fields[0], fields[1], fields[2], ""); e != nil {
			t.Fatal(e)
		}
	}
	rows, e := f.read(ctx, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	if len(rows) != 130 {
		t.Fatalf("snapshot truncated or crossed scope: %d", len(rows))
	}
	clients, epochs := map[string]bool{}, map[string]bool{}
	for _, row := range rows {
		clients[*row.ClientId] = true
		epochs[*row.ChannelEpoch] = true
		if row.Attempt == nil || row.Effect == nil || row.Plan == nil || row.Plan.ContentHash == nil || *row.Plan.ContentHash != f.planHash || len(row.Outcomes) != 0 || row.Effect.State == nil || *row.Effect.State != "intent" {
			t.Fatal("snapshot omitted immutable plan or fabricated missing outcome")
		}
	}
	if len(clients) != 3 || len(epochs) != 130 {
		t.Fatal("reader retained hidden client/epoch filter")
	}
	last := rows[len(rows)-1]
	sort.Strings(ids)
	after := ids[127]
	var pages atomic.Int32
	arrived := ""
	rows, e = f.read(ctx, func(context.Context) error {
		if inReconnectPageAdmission() && pages.Add(1) == 2 {
			var err error
			arrived, err = f.seed("concurrent-client", "concurrent", "profile", "browser", strings.Repeat("a", 64), after)
			if err == nil {
				err = f.outcome(last, "unknown", `{"dispatchState":"unknown","verificationState":"unknown"}`)
			}
			return err
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if pages.Load() != 3 || arrived == "" || len(rows) != 130 {
		t.Fatalf("snapshot admitted concurrent arrival: pages=%d rows=%d arrived=%t", pages.Load(), len(rows), arrived != "")
	}
	for _, row := range rows {
		if *row.Id == arrived {
			t.Fatal("read transaction observed a later page arrival")
		}
		if *row.Id == *last.Id && (*row.Effect.State != "intent" || len(row.Outcomes) != 0) {
			t.Fatal("child relations escaped the root snapshot transaction")
		}
	}
	fresh, e := f.read(ctx, func(context.Context) error { return nil })
	if e != nil || len(fresh) != 131 {
		t.Fatalf("separate snapshot did not see committed arrival: %d %v", len(fresh), e)
	}
	foundOutcome := false
	for _, row := range fresh {
		if *row.Id == *last.Id {
			foundOutcome = true
			if row.Effect == nil || *row.Effect.State != "unknown" || len(row.Outcomes) != 1 || *row.Outcomes[0].PayloadJson != `{"dispatchState":"unknown","verificationState":"unknown"}` {
				t.Fatal("fresh snapshot lost immutable original UNKNOWN outcome")
			}
		}
	}
	if !foundOutcome {
		t.Fatal("updated original binding disappeared")
	}
	pages.Store(0)
	revoked, e := f.read(ctx, func(context.Context) error {
		if inReconnectPageAdmission() {
			pages.Add(1)
			return nil
		}
		if pages.Load() >= 2 {
			return auth.ErrUnauthorized
		}
		return nil
	})
	if e == nil || revoked != nil {
		t.Fatal("final native guard revocation returned stale complete data")
	}
	canceled, stop := context.WithCancel(ctx)
	pages.Store(0)
	partial, e := f.read(canceled, func(context.Context) error {
		if inReconnectPageAdmission() && pages.Add(1) == 2 {
			stop()
		}
		return nil
	})
	if e == nil || partial != nil {
		t.Fatal("canceled second page returned partial coverage")
	}
}

func (f *reconnectGraphFixture) outcome(row *page.Binding, state, payload string) error {
	effect := &commitoutcome.Effect{}
	effect.SetNamespace(row.Namespace)
	effect.SetId(row.EffectId)
	effect.SetAttemptId(row.DurableAttemptId)
	effect.SetRunId(row.RunId)
	effect.SetRevision(row.Effect.Revision)
	effect.SetState(&state)
	effect.SetEvidenceJson(&payload)
	event := &commitoutcome.Event{}
	event.SetNamespace(row.Namespace)
	event.SetId(stringPointer(data.ChromeAttemptRawDigest("outcome-" + *row.Id)))
	event.SetRunId(row.RunId)
	event.SetAttemptId(row.DurableAttemptId)
	event.SetSequence(intPointer(2))
	event.SetKind(stringPointer("outcome"))
	event.SetPayloadJson(&payload)
	event.SetCreatedAt(stringPointer(time.Now().UTC().Format(time.RFC3339Nano)))
	effect.SetEvents([]*commitoutcome.Event{event})
	input := &commitoutcome.CommitOutcomeInput{}
	input.SetNamespace(f.p.Namespace)
	input.SetCommitOutcome([]*commitoutcome.Effect{effect})
	_, err := reconnectInvoke(f.ctx, f.server, "commitoutcome", "CommitOutcome", "PATCH", input)
	return err
}
