package chromeattemptbindingsnapshot

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	page "github.com/viant/mechanize/data/chromeattemptbindingpage"
)

func snapshotCollectorFixture(t *testing.T) (context.Context, auth.Principal, data.ChromeReconnectBindingReadScope) {
	t.Helper()
	p, e := auth.NewPrincipal("fixture", "", "snapshot-capacity", []string{"desktop:control"})
	if e != nil {
		t.Fatal(e)
	}
	p.ClientID = "fixture"
	return auth.WithPrincipal(context.Background(), p), p, data.ChromeReconnectBindingReadScope{ProfileChannel: "profile", BrowserInstance: "browser", ScopeHash: strings.Repeat("a", 64)}
}
func TestSnapshotCapacityAndCursorNeverReturnPartialCoverage(t *testing.T) {
	ctx, p, scope := snapshotCollectorFixture(t)
	ptr := func(s string) *string { return &s }
	for _, total := range []int{4096, 4097} {
		calls := 0
		rows, e := collect(ctx, scope, func(_ context.Context, r exec.ComponentRequest) (any, error) {
			calls++
			in := r.Input.(*page.PageChromeAttemptBindingsInput)
			offset := 0
			if in.AfterID != "" {
				n, e := strconv.ParseInt(in.AfterID, 16, 64)
				if e != nil {
					return nil, e
				}
				offset = int(n)
			}
			out := &page.PageChromeAttemptBindingsOutput{}
			for n := offset + 1; n <= total && len(out.Data) < data.ChromeReconnectBindingPageSize; n++ {
				out.Data = append(out.Data, &page.Binding{Id: ptr(fmt.Sprintf("%064x", n)), Namespace: ptr(p.Namespace), ProfileChannel: ptr(scope.ProfileChannel), BrowserInstance: ptr(scope.BrowserInstance), ScopeHash: ptr(scope.ScopeHash), BrokerEpoch: ptr("broker"), ChannelEpoch: ptr("channel")})
			}
			return out, nil
		})
		if calls != 33 {
			t.Fatalf("terminal page not checked: %d", calls)
		}
		if total == 4096 {
			if e != nil || len(rows) != total {
				t.Fatal("exact capacity rejected", e)
			}
		} else if e == nil || rows != nil {
			t.Fatal("overflow returned partial coverage")
		}
	}
	for _, mode := range []string{"foreign", "duplicate", "oversized"} {
		rows, e := collect(ctx, scope, func(context.Context, exec.ComponentRequest) (any, error) {
			row := &page.Binding{Id: ptr(strings.Repeat("a", 64)), Namespace: ptr(p.Namespace), ProfileChannel: ptr(scope.ProfileChannel), BrowserInstance: ptr(scope.BrowserInstance), ScopeHash: ptr(scope.ScopeHash), BrokerEpoch: ptr("broker"), ChannelEpoch: ptr("channel")}
			out := &page.PageChromeAttemptBindingsOutput{Data: []*page.Binding{row}}
			switch mode {
			case "foreign":
				row.ScopeHash = ptr(strings.Repeat("b", 64))
			case "duplicate":
				out.Data = append(out.Data, row)
			case "oversized":
				row.Plan = &page.Plan{ContentJson: ptr(strings.Repeat("x", 32*1024*1024))}
			}
			return out, nil
		})
		if e == nil || rows != nil {
			t.Fatal("invalid partial snapshot accepted", mode)
		}
	}
}

func TestSnapshotShortPageDoesNotClaimExhaustion(t *testing.T) {
	ctx, p, scope := snapshotCollectorFixture(t)
	ptr := func(s string) *string { return &s }
	calls := 0
	rows, err := collect(ctx, scope, func(_ context.Context, request exec.ComponentRequest) (any, error) {
		calls++
		in := request.Input.(*page.PageChromeAttemptBindingsInput)
		after := 0
		if in.AfterID != "" {
			n, e := strconv.ParseInt(in.AfterID, 16, 64)
			if e != nil {
				return nil, e
			}
			after = int(n)
		}
		out := &page.PageChromeAttemptBindingsOutput{}
		// A selector may return fewer rows than the configured maximum.
		for n := after + 1; n <= 5 && len(out.Data) < 2; n++ {
			out.Data = append(out.Data, &page.Binding{Id: ptr(fmt.Sprintf("%064x", n)), Namespace: ptr(p.Namespace), ProfileChannel: ptr(scope.ProfileChannel), BrowserInstance: ptr(scope.BrowserInstance), ScopeHash: ptr(scope.ScopeHash), BrokerEpoch: ptr("broker"), ChannelEpoch: ptr("channel")})
		}
		return out, nil
	})
	if err != nil || len(rows) != 5 || calls != 4 {
		t.Fatal("short page caused partial coverage", len(rows), calls, err)
	}
}
