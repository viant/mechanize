package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth/nativepeer"
)

func TestBrowserStatusClosedProcessRevalidationReasons(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{
		{"socket", "nativePeerAuthenticationUnavailable"}, {"audit", "nativePeerAuditUnavailable"},
		{"host", "nativeHostIdentityChanged"}, {"chrome", "chromeIdentityChanged"},
		{"scope", "scopeChanged"}, {"channel", "channelChanged"}, {"kernel", "kernelPeerUnqualified"},
		{"ancestry", "desktopAncestryUnqualified"}, {"timeout", "processVerificationExpired"},
		{"signature", "chromeSignatureUnavailable"}, {"raw", "processVerificationUnavailable"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			g, p, ctx, c, _ := setupFixture(t)
			b := g.broker
			b.mu.Lock()
			expected := *c.processEvidence
			c.executorQualified = true
			c.inventoryComplete = true
			c.unknown["retained"] = true
			if tc.mode == "scope" {
				c.scopeQualified = false
			}
			b.mu.Unlock()
			b.verifyPeer = func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
				current := expected
				switch tc.mode {
				case "socket":
					return current, errors.Join(nativepeer.ErrNativePeerAuthentication, errors.New("PRIVATE-CANARY /private/path"))
				case "audit":
					return current, nativepeer.ErrNativePeerAudit
				case "host":
					current.NativeHost.StartToken = "changed"
				case "chrome":
					current.ChromeParent.StartToken = "changed"
				case "kernel":
					current.KernelPeerQualified = false
				case "ancestry":
					current.Ancestors = nil
				case "timeout":
					return current, context.DeadlineExceeded
				case "signature":
					return current, nativepeer.ProcessFailure(nativepeer.ErrChromeSignatureUnavailable, errors.New("PRIVATE-CANARY"))
				case "raw":
					return current, errors.New("PRIVATE-CANARY")
				case "channel":
					b.mu.Lock()
					copy := expected
					c.processEvidence = &copy
					b.mu.Unlock()
				}
				return current, nil
			}
			status, e := b.BrowserStatus(ctx, p)
			if e != nil || len(status.Channels) != 1 {
				t.Fatal(e)
			}
			row := status.Channels[0]
			if row.ProcessVerificationReason != tc.want || !row.Connected || row.ProcessQualified || row.ScopeQualified || row.ExecutorQualified || row.SetupMetadataAvailable || row.UnknownCount != 1 || !row.InventoryComplete {
				t.Fatal("reason or original flags changed", row)
			}
			raw, _ := json.Marshal(status)
			if strings.Contains(string(raw), "CANARY") || strings.Contains(string(raw), "/private/") || strings.Contains(string(raw), "StartToken") {
				t.Fatal("private diagnostic data escaped")
			}
			b.mu.Lock()
			retained := c.conn != nil && c.unknown["retained"]
			b.mu.Unlock()
			if !retained {
				t.Fatal("diagnostic changed authority/history")
			}
		})
	}
}

func TestProcessRevalidationReasonUnknownTextNeverTrusted(t *testing.T) {
	if processVerificationReason(nil) != "" {
		t.Fatal("success reason")
	}
	if processVerificationReason(errors.New("nativeHostIdentityChanged PRIVATE-CANARY")) != "processVerificationUnavailable" {
		t.Fatal("raw text accepted as classification")
	}
}
