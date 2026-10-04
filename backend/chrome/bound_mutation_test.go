package chrome

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBoundMutationRequiresCommitBeforeTransport(t *testing.T) {
	g, p, ctx, count := controlFixtureVersion(t, 2)
	a, e := g.AdmitControl(ctx, p, modelSurfaceFixture())
	if e != nil {
		t.Fatal(e)
	}
	plan, e := script.Compile(`web.tab(origin:"https://fixture.test").getById("save",exact:true).click()`)
	if e != nil {
		t.Fatal(e)
	}
	entered, release := make(chan BoundMutation, 1), make(chan struct{})
	done := make(chan error, 1)
	var calls atomic.Int32
	go func() {
		r, e := g.ExecuteControlBound(ctx, p, plan.Steps[0], nil, a, strings.Repeat("a", 64), func(c context.Context, actor auth.Principal, d BoundMutation) (BindingCommit, error) {
			calls.Add(1)
			entered <- d
			<-release
			return BindingCommit{BindingID: strings.Repeat("b", 64), CommitConfirmed: true, ReadbackMatched: true}, nil
		})
		if e == nil && r.DispatchState != "dispatched" {
			e = errors.New("dispatch receipt missing")
		}
		done <- e
	}()
	var descriptor BoundMutation
	select {
	case descriptor = <-entered:
	case <-time.After(time.Second):
		t.Fatal("binding callback not invoked")
	}
	if count.Load() != 0 {
		t.Fatal("transport happened before binding commit")
	}
	if descriptor.BrowserAttemptID != strings.Repeat("a", 64) || descriptor.Identity != a.Document.Identity || descriptor.BrokerEpoch != a.BrokerEpoch || descriptor.ChannelEpoch != a.ChannelEpoch || descriptor.ScopeHash != a.ScopeHash || descriptor.ControlLease != a.Lease || descriptor.Fingerprint.Version != 2 || len(descriptor.Fingerprint.SHA256) != 64 {
		t.Fatalf("logical descriptor changed %+v", descriptor)
	}
	// The callback runs outside all broker/control/write locks: readonly authority
	// validation remains available while its persistence is deliberately blocked.
	verify := make(chan error, 1)
	go func() { verify <- g.VerifyControl(ctx, p, a) }()
	select {
	case e := <-verify:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("binding callback held broker/control mutex")
	}
	close(release)
	if e = <-done; e != nil || count.Load() != 1 || calls.Load() != 1 {
		t.Fatalf("bound send failed %v count%d commits%d", e, count.Load(), calls.Load())
	}
}

func TestBoundMutationCommitFailureCancelAndAuthorityChangesNeverSend(t *testing.T) {
	for _, mode := range []string{"error", "unconfirmed", "unmatched", "invalidID", "cancel", "revoke", "documentChanged", "channelChanged", "callbackDescriptorCopy"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, count := controlFixtureVersion(t, 2)
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			a, e := g.AdmitControl(ctx, p, modelSurfaceFixture())
			if e != nil {
				t.Fatal(e)
			}
			plan, _ := script.Compile(`web.tab(origin:"https://fixture.test").getById("save",exact:true).click()`)
			calls := 0
			result, e := g.ExecuteControlBound(ctx, p, plan.Steps[0], nil, a, strings.Repeat("a", 64), func(c context.Context, actor auth.Principal, d BoundMutation) (BindingCommit, error) {
				calls++
				commit := BindingCommit{BindingID: strings.Repeat("b", 64), CommitConfirmed: true, ReadbackMatched: true}
				switch mode {
				case "error":
					return BindingCommit{}, errors.New("PRIVATE_DATA should not escape")
				case "unconfirmed":
					commit.CommitConfirmed = false
				case "unmatched":
					commit.ReadbackMatched = false
				case "invalidID":
					commit.BindingID = "wrong"
				case "cancel":
					cancel()
				case "revoke":
					if _, err := g.RetireControl(c, p, a); err != nil {
						t.Fatal(err)
					}
				case "documentChanged":
					g.broker.mu.Lock()
					g.controlChannelUnlocked(a).documents[0].Generation++
					g.broker.mu.Unlock()
				case "channelChanged":
					g.broker.mu.Lock()
					g.controlChannelUnlocked(a).epoch = "changed"
					g.broker.mu.Unlock()
				case "callbackDescriptorCopy":
					d.Identity.DocumentID = "foreign"
					d.Fingerprint.SHA256 = strings.Repeat("c", 64)
					commit.ReadbackMatched = false
				}
				return commit, nil
			})
			if e == nil || result.DispatchState != "notDispatched" || count.Load() != 0 || calls != 1 {
				t.Fatalf("failed seal reached transport %+v %v count%d calls%d", result, e, count.Load(), calls)
			}
			if strings.Contains(e.Error(), "PRIVATE_DATA") {
				t.Fatal("callback payload echoed")
			}
		})
	}
}
func (g *Gateway) controlChannelUnlocked(a ControlAuthority) *channel {
	return g.broker.channels[channelKey(a.Document.ProfileChannel, a.Document.BrowserInstance)]
}

func TestBoundMutationRequiresExplicitWorkerAndDocumentV2(t *testing.T) {
	for _, mode := range []string{"legacy", "missingCallback", "wrongDocument", "wrongAttempt"} {
		t.Run(mode, func(t *testing.T) {
			version := 2
			if mode == "legacy" {
				version = 0
			}
			g, p, ctx, count := controlFixtureVersion(t, version)
			a, e := g.AdmitControl(ctx, p, modelSurfaceFixture())
			if e != nil {
				t.Fatal(e)
			}
			plan, _ := script.Compile(`web.tab(origin:"https://fixture.test").getById("save",exact:true).click()`)
			calls := 0
			callback := CommitMutationBinding(func(context.Context, auth.Principal, BoundMutation) (BindingCommit, error) {
				calls++
				return BindingCommit{}, nil
			})
			attempt := strings.Repeat("a", 64)
			if mode == "missingCallback" {
				callback = nil
			}
			if mode == "wrongDocument" {
				a.Document.MutationFingerprintVersion = 1
			}
			if mode == "wrongAttempt" {
				attempt = "run-plan-step"
			}
			r, e := g.ExecuteControlBound(ctx, p, plan.Steps[0], nil, a, attempt, callback)
			if e == nil || r.DispatchState != "notDispatched" || calls != 0 || count.Load() != 0 {
				t.Fatal("unnegotiated mutation entered seal/transport", r, e, calls, count.Load())
			}
		})
	}
}

func modelSurfaceFixture() model.Surface {
	return model.Surface{Kind: "web", Origin: "https://fixture.test"}
}

func TestBoundMutationHistoryNeverRecommitsOrReplays(t *testing.T) {
	for _, mode := range []string{"known", "unknown", "conflict", "otherUnknown"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, count := controlFixtureVersion(t, 2)
			a, e := g.AdmitControl(ctx, p, modelSurfaceFixture())
			if e != nil {
				t.Fatal(e)
			}
			plan, _ := script.Compile(`web.tab(origin:"https://fixture.test").getById("save",exact:true).click()`)
			attempt := strings.Repeat("a", 64)
			command := Command{Action: "element.press", Identity: a.Document.Identity, AttemptID: attempt, ControlLease: &a.Lease, Locator: &Locator{Strategy: "id", Value: "save", Exact: true}, BrokerEpoch: a.BrokerEpoch, ChannelEpoch: a.ChannelEpoch, ScopeHash: a.ScopeHash, FingerprintVersion: 2}
			fingerprint, e := FingerprintMutationV2(command)
			if e != nil {
				t.Fatal(e)
			}
			command.FingerprintSHA256 = fingerprint.SHA256
			c := g.controlChannel(a)
			g.broker.mu.Lock()
			if mode == "otherUnknown" {
				c.unknown["other"] = true
			} else {
				retained := command
				retained.Args = nil
				retained.Locator = nil
				if mode == "conflict" {
					retained.FingerprintSHA256 = strings.Repeat("c", 64)
				}
				c.attempts[attempt] = retained
				if mode == "known" {
					c.receipts[attempt] = Reply{AttemptID: attempt, Identity: command.Identity, DispatchState: "dispatched", EffectState: "unverified", FingerprintVersion: 2, FingerprintSHA256: command.FingerprintSHA256}
				} else {
					c.unknown[attempt] = true
				}
			}
			g.broker.mu.Unlock()
			commits := 0
			result, e := g.ExecuteControlBound(ctx, p, plan.Steps[0], nil, a, attempt, func(context.Context, auth.Principal, BoundMutation) (BindingCommit, error) {
				commits++
				return BindingCommit{}, errors.New("must not recommit")
			})
			if mode == "known" {
				if e != nil || result.DispatchState != "dispatched" {
					t.Fatal("known original receipt lost", result, e)
				}
			} else if e == nil || result.DispatchState != "unknown" {
				t.Fatal("original uncertainty downgraded", result, e)
			}
			if commits != 0 || count.Load() != 0 {
				t.Fatal("history replayed or recommitted", commits, count.Load())
			}
		})
	}
}
