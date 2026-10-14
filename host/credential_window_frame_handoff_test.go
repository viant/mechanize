package host

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	gateway "github.com/viant/mechanize/mcp"
)

func TestCredentialPreparationRetiresOnlyOwnedUnusedInspectionFrame(t *testing.T) {
	for _, mode := range []string{"unused", "used", "foreignClient", "foreignSession"} {
		t.Run(mode, func(t *testing.T) {
			credentialHostFixtureFlow(t, "known", credentialHostFixtureHooks{beforeStatus: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, browser *credentialBrowserFixture, reads *atomic.Int64) {
				release, err := h.vaultExposure.AcquireNativeExposureContext(ctx)
				if err != nil {
					t.Fatal(err)
				}
				retained, cancel := context.WithCancel(ctx)
				old := &windowFramePermit{principal: p, binding: auth.ConsentBinding{SessionID: input.SessionID}, ready: true, cancel: cancel, done: make(chan struct{}), lease: &consent.Lease{Context: retained, Release: release}}
				if mode == "used" {
					old.used = true
				}
				if mode == "foreignClient" {
					old.principal.ClientID = "another-client"
				}
				if mode == "foreignSession" {
					old.binding.SessionID = "another-session"
				}
				h.framePermits = map[string]*windowFramePermit{p.Namespace: old}
				before := reads.Load()
				status, err := h.CredentialStatus(ctx, p, ref)
				if mode == "unused" {
					if err != nil || status.State != "ready" || browser.admissions != 1 {
						t.Fatal("owned inspection frame stranded private preparation", status, err)
					}
					select {
					case <-old.done:
					default:
						t.Fatal("private preparation preceded actual frame retirement")
					}
					if !old.retiring || old.lease.Context.Err() == nil || reads.Load() != before {
						t.Fatal("retirement changed input/private read boundary")
					}
				} else {
					if err != nil || status.State != "needsNativeAction" || status.AttentionCode != "entryProtection" || browser.admissions != 0 || old.retiring || reads.Load() != before {
						t.Fatal("foreign/live inspection interval lost protection", status, err)
					}
					// Cleanup fixture-owned exposure after barrier assertions, no input replay.
					h.frameMu.Lock()
					old.used = false
					h.frameMu.Unlock()
					_ = h.retireWindowFrame(old)
				}
			}})
		})
	}
}
