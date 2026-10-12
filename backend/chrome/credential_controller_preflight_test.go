package chrome

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

// Real broker reader/socket, canonical controller dispatch and Datly user lock.
// Only signed peer identity and the renderer replies are synthetic boundaries.
func TestControllerPreflightSocketKeepsKnownRepliesAndUnrelatedFramesSeparate(t *testing.T) {
	for _, kind := range []string{"ready", "controllerMetadata", "notReady", "parallelStatus", "invalidExtraArgs", "controllerClosed", "staleClose", "bookkeeping"} {
		t.Run(kind, func(t *testing.T) {
			g, _, _, conn, c, doc := credentialAdmissionFixture(t)
			b := g.broker
			dispatcher := &controllerDispatchFixture{closed: make(chan struct{}, 1)}
			b.controllerDispatcher = dispatcher
			b.mu.Lock()
			c.grant.Principal.Scopes = append(c.grant.Principal.Scopes, "desktop:observe")
			c.workerBuild = 32
			c.privateInspectionDiagnosticVersion = 1
			c.controllerPolicy = ControllerPolicy{Enabled: true, Origins: []string{"https://shell.fixture.test"}}
			s := &ControllerSession{ID: "owned-port", Origin: "https://shell.fixture.test", DocumentID: "controller-document", Approved: true, ExpiresAt: time.Now().Add(time.Minute)}
			c.controllerSessions[s.ID] = s
			b.initControllerSessionLocked(c, s)
			actor := s.identity.Principal
			req := controllerRequest{Type: "controllerRequest", RequestID: "status-first", Operation: "tools/call", Params: &ControllerToolCall{Name: "mechanize_credential_status", Arguments: json.RawMessage(`{"sessionId":"runtime-owned","preparationId":"` + strings.Repeat("f", 64) + `"}`)}, Origin: s.Origin, DocumentID: s.DocumentID, SessionID: s.ID, BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, Deadline: time.Now().Add(8 * time.Second).UnixMilli()}
			b.mu.Unlock()
			ctx := auth.WithConsentBinding(auth.WithPrincipal(context.Background(), actor), auth.ConsentBinding{SessionID: "runtime-owned", GrantID: "fixture-grant", Purpose: "private fixture"})
			_, file, _, _ := runtime.Caller(0)
			store, e := durable.New(durable.Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) {
				t.Fatal("preflight asked for input lease")
				return 0, nil
			}}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
				t.Error("preflight dispatched input")
				return integration.StepResult{}, nil
			})
			if e != nil {
				t.Fatal(e)
			}
			defer store.Close(context.Background())
			// Warm only the actual typed user pool; caller deadline starts at dispatch.
			if _, e = store.CredentialDeliveryBlocked(ctx, actor); e != nil {
				t.Fatal(e)
			}
			dispatcher.call = func(callctx context.Context, id ControllerIdentity, _ ControllerToolCall) (*schema.CallToolResult, error) {
				callctx = auth.WithConsentBinding(callctx, auth.ConsentBinding{SessionID: "runtime-owned", GrantID: "fixture-grant", Purpose: "private fixture"})
				var admission ControlAdmission
				e := store.WithCredentialDeliveryComponents(callctx, id.Principal, func(held context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
					prep := data.CredentialPreparationRecord{Namespace: actor.Namespace, ClientID: actor.ClientID, SessionID: "runtime-owned", PreparationID: strings.Repeat("f", 64), GrantID: "fixture-grant", PurposeHash: data.CredentialDeliveryPurposeHash("private fixture"), Origin: doc.Origin, SelectedRevision: strings.Repeat("e", 64), ProtectionState: "held", Revision: 1, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
					sealed, revoke, e := data.WithCredentialPreparationAuthority(held, prep, func(c context.Context) error { return c.Err() })
					if e != nil {
						return e
					}
					defer revoke()
					if e = store.ReserveCredentialPreparation(sealed, id.Principal); e != nil {
						return e
					}
					admission, e = g.AdmitCredentialControl(held, id.Principal, model.Surface{Kind: "web", Origin: doc.Origin}, func(c context.Context) error { return c.Err() })
					return e
				})
				state := "ready"
				if e != nil {
					state = "needsNativeAction"
				}
				return &schema.CallToolResult{StructuredContent: map[string]any{"state": state, "phase": admission.FailureStage, "reason": admission.FailureReason}}, nil
			}
			b.controllerDispatcher = dispatcher
			req.Deadline = time.Now().Add(8 * time.Second).UnixMilli()
			if e = WriteFrame(conn, req); e != nil {
				t.Fatal(e)
			}
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			raw, e := ReadFrame(conn)
			if e != nil {
				t.Fatal("inspection request unavailable", e)
			}
			var inspect struct {
				Type, RequestID string
				Identity        Identity
				RecipientID     string
				Diagnostics     bool
			}
			if json.Unmarshal(raw, &inspect) != nil || inspect.Type != "credentialInspect" || !inspect.Diagnostics || inspect.RecipientID == "" {
				t.Fatal("production build32 preflight wire missing")
			}
			if kind == "staleClose" {
				if e = WriteFrame(conn, map[string]any{"type": "controllerClosed", "sessionId": s.ID, "brokerEpoch": req.BrokerEpoch + "-stale", "channelEpoch": req.ChannelEpoch, "scopeHash": req.ScopeHash}); e != nil {
					t.Fatal(e)
				}
			}
			if kind == "bookkeeping" {
				if e = WriteFrame(conn, map[string]any{"type": "controllerSync", "brokerEpoch": req.BrokerEpoch, "channelEpoch": req.ChannelEpoch, "scopeHash": req.ScopeHash}); e != nil {
					t.Fatal(e)
				}
				if e = WriteFrame(conn, map[string]any{"type": "controllerClosed", "sessionId": "unrelated-port", "brokerEpoch": req.BrokerEpoch, "channelEpoch": req.ChannelEpoch, "scopeHash": req.ScopeHash}); e != nil {
					t.Fatal(e)
				}
			}
			if kind == "controllerClosed" {
				if e = WriteFrame(conn, map[string]any{"type": "controllerClosed", "sessionId": s.ID, "brokerEpoch": req.BrokerEpoch, "channelEpoch": req.ChannelEpoch, "scopeHash": req.ScopeHash}); e != nil {
					t.Fatal(e)
				}
				select {
				case <-s.ctx.Done():
				case <-time.After(500 * time.Millisecond):
					t.Fatal("owned close failed to cancel pending inspection")
				}
				if blocked, e := store.CredentialDeliveryBlocked(ctx, actor); e != nil || !blocked {
					t.Fatal("cancellation erased the durable preparation")
				}
				b.mu.Lock()
				inputs := len(c.pending) + len(c.unknown)
				b.mu.Unlock()
				if inputs != 0 {
					t.Fatal("cancellation created an input attempt")
				}
				return
			}
			if kind == "controllerMetadata" || kind == "parallelStatus" || kind == "invalidExtraArgs" {
				other := req
				other.RequestID = "interleaved-metadata"
				if kind == "controllerMetadata" {
					other.Operation = "connection.status"
					other.Params = nil
				}
				if kind == "invalidExtraArgs" {
					other.Params = &ControllerToolCall{Name: "mechanize_credential_status", Arguments: json.RawMessage(`{"sessionId":"runtime-owned","preparationId":"` + strings.Repeat("f", 64) + `","value":"private-canary"}`)}
				}
				if e = WriteFrame(conn, other); e != nil {
					t.Fatal(e)
				}
			}
			identity := inspect.Identity
			identity.Generation++
			ready := kind != "notReady"
			reason := "none"
			stage := "pair"
			if !ready {
				reason = "noCredentialFields"
				stage = "unavailable"
			}
			if e = WriteFrame(conn, map[string]any{"type": "credentialInspectResult", "requestId": inspect.RequestID, "identity": identity, "ready": ready, "stage": stage, "privateCredentialProtocolVersion": 3, "recipientId": inspect.RecipientID, "inspectionReason": reason}); e != nil {
				t.Fatal(e)
			}
			if ready {
				raw, e = ReadFrame(conn)
				if e != nil {
					t.Fatal("interleaved frame poisoned private inspection", e)
				}
				var acquire Command
				if json.Unmarshal(raw, &acquire) != nil || acquire.Action != "executor.acquire" {
					t.Fatal("acquisition wire missing")
				}
				if e = WriteFrame(conn, map[string]any{"requestId": acquire.RequestID, "identity": acquire.Identity, "validated": true, "controlLease": acquire.ControlLease}); e != nil {
					t.Fatal(e)
				}
			}
			// The queued refusal may win the write lane before the original
			// success. Both requests get separate truthful completions.
			var original []byte
			refused := false
			count := 1
			if kind == "controllerMetadata" || kind == "parallelStatus" || kind == "invalidExtraArgs" {
				count = 2
			}
			for n := 0; n < count; n++ {
				raw, e = ReadFrame(conn)
				if e != nil {
					t.Fatal("known preflight outcome lost by transport closure", e)
				}
				var envelope struct {
					RequestID string
					Result    struct {
						IsError           bool
						StructuredContent struct{ Code, DispatchState string }
					}
				}
				if json.Unmarshal(raw, &envelope) != nil {
					t.Fatal("controller outcome invalid")
				}
				if envelope.RequestID == req.RequestID {
					original = raw
					continue
				}
				if envelope.RequestID != "interleaved-metadata" || !envelope.Result.IsError || envelope.Result.StructuredContent.Code != "controllerToolRejected" || envelope.Result.StructuredContent.DispatchState != "notDispatched" {
					t.Fatal("distinct refusal lacked truthful no-dispatch result")
				}
				refused = true
			}
			if count == 2 && !refused {
				t.Fatal("concurrent or invalid request disappeared")
			}
			if dispatcher.calls.Load() != 1 {
				t.Fatal("parallel request executed/coalesced instead of separate refusal")
			}
			raw = original
			var result struct {
				Type, RequestID, Error string
				Result                 struct {
					StructuredContent struct{ State, Phase, Reason string }
				}
			}
			if json.Unmarshal(raw, &result) != nil || result.Type != "controllerResult" || result.RequestID != req.RequestID || result.Error != "" {
				t.Fatal("canonical outcome missing")
			}
			if ready && result.Result.StructuredContent.State != "ready" || !ready && (result.Result.StructuredContent.State != "needsNativeAction" || result.Result.StructuredContent.Reason != "noCredentialFields") {
				t.Fatal("known preflight outcome changed")
			}
			if kind == "notReady" {
				guard := func(c context.Context) error {
					return g.VerifyCredentialPreflightIdle(c, actor, strings.Repeat("f", 64), doc.Origin)
				}
				if e = store.WithCredentialDeliveryComponents(ctx, actor, func(held context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
					prep, children, e := store.LoadCredentialRecovery(held, actor, strings.Repeat("f", 64))
					if e != nil || len(children) != 0 {
						t.Fatal("known negative created input history")
					}
					clean, stop, e := data.WithCredentialPreflightCleanupAuthority(held, prep, guard)
					if e != nil {
						return e
					}
					defer stop()
					prep.ProtectionState = "closed"
					prep.Revision++
					bound, revoke, e := data.WithCredentialPreparationAuthority(clean, prep, guard)
					if e != nil {
						return e
					}
					defer revoke()
					if e = store.CloseCredentialPreparation(bound, actor); e != nil {
						return e
					}
					return g.RetireCredentialPreflight(bound, actor, prep.PreparationID, prep.Origin)
				}); e != nil {
					t.Fatal("typed zero-child cleanup retained completed no-input interceptor", e)
				}
				b.mu.Lock()
				retained := c.privateInspection != nil
				b.mu.Unlock()
				if retained {
					t.Fatal("known-negative interceptor survived typed retirement")
				}
			}
			b.mu.Lock()
			alive := c.conn != nil
			pending := len(c.pending)
			unknown := len(c.unknown)
			b.mu.Unlock()
			if !alive || pending != 0 || unknown != 0 {
				t.Fatal("metadata-only preflight closed transport or created an input receipt")
			}
		})
	}
}
