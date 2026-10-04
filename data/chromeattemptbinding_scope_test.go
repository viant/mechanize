package data

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
)

func bindingAuthorityFixture(t *testing.T) (context.Context, auth.Principal, ChromeAttemptBindingAuthority, func()) {
	t.Helper()
	p, _ := auth.NewPrincipal("fixture", "", "binding-owner", []string{"desktop:control"})
	p.ClientID = "enrolled-client"
	ctx, err := WithScope(auth.WithPrincipal(context.Background(), p), Scope{Namespace: p.Namespace, LeaseEpoch: 7})
	if err != nil {
		t.Fatal(err)
	}
	attempt := ChromeRetirementDigest([]string{"attempt-resume", "run", "plan", "step", "operation"})
	effect := ChromeRetirementDigest([]string{"effect", attempt})
	record := CommittedStepIntent{Namespace: p.Namespace, ClientID: p.ClientID, RunID: "run", PlanID: "plan", StepID: "step", StepIndex: 0, AttemptID: attempt, EffectID: effect, LeaseEpoch: 7, RunRevision: 4, SessionID: "session", OperationID: "operation"}
	ctx, revoke, err := WithCommittedStepIntent(ctx, p, record)
	if err != nil {
		t.Fatal(err)
	}
	a := ChromeAttemptBindingAuthority{Namespace: p.Namespace, ClientID: p.ClientID, RunID: record.RunID, PlanID: record.PlanID, StepID: record.StepID, DurableAttemptID: attempt, EffectID: effect, ProfileChannel: "profile", BrowserInstance: "browser", BrokerEpoch: "broker", ChannelEpoch: "channel", ScopeHash: strings.Repeat("a", 64), TabID: 7, DocumentID: "document", DocumentGeneration: 1, RendererLeaseID: "lease", RendererLeaseGeneration: 7, FingerprintVersion: 2, FingerprintDigest: strings.Repeat("b", 64), PlanContentDigest: strings.Repeat("c", 64), StepDigest: strings.Repeat("d", 64), BusinessKeyDigest: strings.Repeat("e", 64), CommittedRunRevision: 4, EndlySessionID: "session", EndlyOperationID: "operation", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), GuardProof: "held-native-peer-renderer-guard"}
	a.ID = ChromeAttemptBindingID(a.Namespace, a.ClientID, attempt)
	a.BrowserAttemptID = ChromeAttemptBrowserIDV2(a.Namespace, a.ClientID, attempt)
	return ctx, p, a, revoke
}

func TestChromeAttemptBindingAuthorityCopiesAndRevokesActualResumedIntent(t *testing.T) {
	ctx, p, a, revoke := bindingAuthorityFixture(t)
	bound, err := WithChromeAttemptBindingAuthority(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	original := a
	a.FingerprintDigest = strings.Repeat("f", 64)
	got, err := RequireChromeAttemptBindingAuthority(bound)
	if err != nil || got != original {
		t.Fatal("sealed authority was not detached", err)
	}
	got.DocumentID = "changed"
	again, err := RequireChromeAttemptBindingAuthority(bound)
	if err != nil || again.DocumentID != original.DocumentID {
		t.Fatal("returned authority aliases sealed fields", err)
	}
	if _, err = RequireChromeAttemptBindingAuthority(WithoutCommittedStepIntent(bound)); err == nil {
		t.Fatal("readonly context inherited binding authority")
	}
	other := p
	other.ClientID = "other-client"
	if _, err = RequireChromeAttemptBindingAuthority(auth.WithPrincipal(bound, other)); err == nil {
		t.Fatal("foreign client reused binding authority")
	}
	revoke()
	if _, err = RequireChromeAttemptBindingAuthority(context.WithoutCancel(bound)); err == nil {
		t.Fatal("binding survived synchronous intent revocation")
	}
}

func TestChromeAttemptBindingAuthorityRejectsWrongFacts(t *testing.T) {
	for _, mode := range []string{"actualAttempt", "effect", "browserAttempt", "client", "runRevision", "operation", "rendererGeneration", "subframe", "version", "unsafeGeneration", "unqualifiedGuard", "stale", "control", "missingIntent", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, p, a, revoke := bindingAuthorityFixture(t)
			defer revoke()
			switch mode {
			case "actualAttempt":
				a.DurableAttemptID = ChromeRetirementDigest([]string{"attempt", "run", "plan", "step"})
			case "effect":
				a.EffectID = strings.Repeat("f", 64)
			case "browserAttempt":
				a.BrowserAttemptID = ChromeAttemptRawDigest("v1-run-plan-step")
			case "client":
				a.ClientID = "foreign"
			case "runRevision":
				a.CommittedRunRevision++
			case "operation":
				a.EndlyOperationID = "foreign"
			case "rendererGeneration":
				a.RendererLeaseGeneration++
			case "subframe":
				a.FrameID = 1
			case "version":
				a.FingerprintVersion = 1
			case "unsafeGeneration":
				a.DocumentGeneration = 9007199254740992
			case "unqualifiedGuard":
				a.GuardProof = ""
			case "stale":
				a.CreatedAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
			case "control":
				p.Scopes = nil
				ctx = auth.WithPrincipal(ctx, p)
			case "missingIntent":
				ctx = WithoutCommittedStepIntent(ctx)
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := WithChromeAttemptBindingAuthority(ctx, a); err == nil {
				t.Fatal("invalid binding authority minted")
			}
		})
	}
}
