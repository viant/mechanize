package chrome

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"strings"
	"testing"
	"time"
)

func TestConsentReconnectProofRequiresActualPreparedHandshakeAndUnchangedInventory(t *testing.T) {
	for _, mode := range []string{"complete", "build33", "build34", "build35", "build36", "futureBuild", "retiredUnknown", "retiredMissingProof", "retiredWrongLease", "absent", "notPrepared", "newChallenge", "documentChanged", "activeWork", "unknown", "private", "newWorkCompleted", "peerChanged", "foreign", "incomplete"} {
		t.Run(mode, func(t *testing.T) {
			build := 32
			switch mode {
			case "build33":
				build = 33
			case "build34":
				build = 34
			case "build35":
				build = 35
			case "build36":
				build = 36
			case "futureBuild":
				build = 37
			}
			f := newLifecycleFixtureBuild(t, 0, build, mode != "absent")
			b, c := f.gateway.broker, f.channel
			p, ctx := f.principal, f.ctx
			b.mu.Lock()
			expectedBuild := build
			if mode == "futureBuild" {
				expectedBuild = 0
			}
			if mode == "absent" {
				expectedBuild = 0
			}
			if c.workerBuild != expectedBuild {
				b.mu.Unlock()
				t.Fatalf("worker build qualification: got %d, want %d", c.workerBuild, expectedBuild)
			}
			if strings.HasPrefix(mode, "retired") {
				id := strings.Repeat("d", 64)
				identity := c.documents[0].Identity
				identity.DocumentID = "retired-source"
				lease := Lease{ID: "original-lease", Generation: 1}
				command := Command{Identity: identity, AttemptID: id, BrokerEpoch: "prior-broker", ChannelEpoch: "prior-channel", ScopeHash: c.scopeHash, ControlLease: &lease, FingerprintVersion: 2, FingerprintSHA256: strings.Repeat("e", 64)}
				c.attempts[id] = command
				c.receipts[id] = Reply{Identity: identity, AttemptID: id, ControlLease: &lease, FingerprintVersion: 2, FingerprintSHA256: command.FingerprintSHA256, DispatchState: "unknown", EffectState: "unknown"}
				c.retiredTargets = map[string]Command{id: command}
				if mode == "retiredMissingProof" {
					c.retiredTargets = nil
				}
				if mode == "retiredWrongLease" {
					other := command
					copied := lease
					copied.ID = "foreign-lease"
					other.ControlLease = &copied
					c.retiredTargets[id] = other
				}
			}
			switch mode {
			case "notPrepared":
				c.consentReconnect.prepared = false
			case "newChallenge":
				c.executorChallenge = "other"
			case "documentChanged":
				c.documents[0].Generation++
			case "activeWork":
				c.pending["active"] = &pending{}
			case "unknown":
				c.unknown["old-unknown"] = true
			case "private":
				c.privateFlow = &credentialFlow{}
			case "newWorkCompleted":
				c.invalidateConsentReconnect()
			case "peerChanged":
				f.badPeer.Store(true)
			case "foreign":
				p.ClientID = "foreign"
			case "incomplete":
				c.inventoryComplete = false
			}
			b.mu.Unlock()
			calls := 0
			err := f.gateway.WithConsentReconnectProof(ctx, p, func() error { calls++; return nil })
			expected := mode == "complete" || mode == "build33" || mode == "build34" || mode == "build35" || mode == "build36" || mode == "retiredUnknown"
			if (err == nil) != expected || calls != map[bool]int{true: 1, false: 0}[expected] {
				t.Fatalf("mode%s calls%d err%v", mode, calls, err)
			}
			b.mu.Lock()
			if mode == "unknown" && !c.unknown["old-unknown"] {
				t.Fatal("unknown erased")
			}
			if mode == "private" && c.privateFlow == nil {
				t.Fatal("private scope erased")
			}
			b.mu.Unlock()
			if f.commands.Load() != 0 {
				t.Fatal("proof dispatched a renderer command")
			}
		})
	}
}
func TestConsentReconnectProofHoldsLanesThroughCommitAndDoesNotRetry(t *testing.T) {
	f := newLifecycleFixture(t, 0, true)
	b, c := f.gateway.broker, f.channel
	failure := errors.New("CAS unavailable")
	called := 0
	err := f.gateway.WithConsentReconnectProof(f.ctx, f.principal, func() error {
		called++
		if c.writeMu.TryLock() {
			c.writeMu.Unlock()
			t.Fatal("channel write lane not held")
		}
		select {
		case b.lane <- struct{}{}:
			<-b.lane
			t.Fatal("input lane not held")
		default:
		}
		select {
		case f.gateway.admissionLane <- struct{}{}:
			<-f.gateway.admissionLane
			t.Fatal("authority admission lane not held")
		default:
		}
		return failure
	})
	if !errors.Is(err, failure) || called != 1 {
		t.Fatal("commit lost or replayed", err, called)
	}
	if !c.writeMu.TryLock() {
		t.Fatal("guard leaked write lane")
	}
	c.writeMu.Unlock()
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if err = f.gateway.WithConsentReconnectProof(ctx, f.principal, func() error { t.Fatal("canceled proof committed"); return nil }); err == nil {
		t.Fatal("canceled proof accepted")
	}
}
func TestConsentReconnectProofDeadlineWaitingWriteLane(t *testing.T) {
	f := newLifecycleFixture(t, 0, true)
	f.channel.writeMu.Lock()
	defer f.channel.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(f.ctx, 25*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := f.gateway.WithConsentReconnectProof(ctx, f.principal, func() error { t.Fatal("blocked proof committed"); return nil })
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("unbounded proof lane", err)
	}
}
func TestConsentReconnectProofRejectsChangedDocumentPublicationAndMalformedPrior(t *testing.T) {
	f := newLifecycleFixture(t, 0, true)
	b, c := f.gateway.broker, f.channel
	b.mu.Lock()
	c.documents[0].DocumentID = "replacement"
	c.observeConsentReconnectInventory()
	if c.consentReconnect != nil {
		t.Fatal("changed publication retained seal")
	}
	for _, raw := range []string{`{}`, `{"brokerEpoch":"old","brokerEpoch":"duplicate"}`, `null`} {
		if newConsentReconnectProof(c, c.conn, b.epoch, []byte(raw)) != nil {
			t.Fatal("malformed prior grant minted proof")
		}
	}
	b.mu.Unlock()
	p := f.principal
	p.ClientID = "foreign"
	ctx := auth.WithPrincipal(f.ctx, p)
	if err := f.gateway.WithConsentReconnectProof(ctx, f.principal, func() error { t.Fatal("foreign actor committed"); return nil }); err == nil {
		t.Fatal("foreign actor accepted")
	}
}

func TestConsentReconnectProofAllowsFreshReadThenCannotBeReusedAfterWork(t *testing.T) {
	f := newLifecycleFixture(t, 0, true)
	committed := 0
	if err := f.gateway.WithConsentReconnectProof(f.ctx, f.principal, func() error { committed++; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := f.gateway.Observe(f.ctx, f.principal, model.Surface{Kind: "web", Origin: "https://fixture.test"}); err != nil {
		t.Fatal("fresh qualified read after cleanup", err)
	}
	if committed != 1 || f.commands.Load() != 1 {
		t.Fatal("read/commit count changed")
	}
	if err := f.gateway.WithConsentReconnectProof(f.ctx, f.principal, func() error { t.Fatal("used proof committed"); return nil }); err == nil {
		t.Fatal("used seal accepted")
	}
}
