package chrome

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"time"

	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

type TabInventory struct {
	Documents   []Document `json:"documents"`
	Complete    bool       `json:"complete"`
	ObservedAt  time.Time  `json:"observedAt"`
	Unavailable []string   `json:"unavailable,omitempty"`
}
type BrowserResult struct {
	integration.StepResult
	Ready    bool      `json:"ready"`
	Active   bool      `json:"active"`
	Document *Document `json:"document,omitempty"`
}

func (g *Gateway) ListTabs(ctx context.Context, p auth.Principal) (TabInventory, error) {
	if err := authorize(ctx, p, false); err != nil {
		return TabInventory{}, err
	}
	result := TabInventory{Complete: true}
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	found := false
	for _, c := range g.broker.channels {
		if c.grant.Principal.Namespace != p.Namespace {
			continue
		}
		found = true
		if c.conn == nil || !c.inventoryComplete {
			result.Complete = false
			continue
		}
		if result.ObservedAt.IsZero() || c.inventoryAt.Before(result.ObservedAt) {
			result.ObservedAt = c.inventoryAt
		}
		for _, d := range c.documents {
			if d.FrameID == 0 {
				result.Documents = append(result.Documents, d)
			}
		}
	}
	if !found {
		result.Complete = false
	}
	if !result.Complete {
		result.Unavailable = []string{"One or more enrolled profiles have no complete live inventory"}
	}
	return result, nil
}
func (g *Gateway) Navigate(ctx context.Context, p auth.Principal, surface model.Surface, destination, attemptID string) (BrowserResult, error) {
	return g.browserAction(ctx, p, surface, "browser.navigate", destination, attemptID)
}
func (g *Gateway) ActivateTab(ctx context.Context, p auth.Principal, surface model.Surface, attemptID string) (BrowserResult, error) {
	return g.browserAction(ctx, p, surface, "browser.activate", "", attemptID)
}
func (g *Gateway) browserAction(ctx context.Context, p auth.Principal, surface model.Surface, action, destination, attemptID string) (BrowserResult, error) {
	result := BrowserResult{StepResult: integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}}
	if err := authorize(ctx, p, true); err != nil {
		return result, err
	}
	if attemptID == "" || len(attemptID) > 128 {
		return result, browserError("attemptIdentityRequired", "Explicit durable browser mutation attempt identity required", "notDispatched")
	}
	c, d, err := g.broker.selectDocument(p, surface)
	if err != nil {
		return result, err
	}
	if !c.grant.Principal.HasScope("desktop:control") {
		return result, auth.ErrUnauthorized
	}
	if action == "browser.navigate" {
		parsed, e := url.Parse(destination)
		if e != nil || len(destination) > 8192 || parsed.User != nil || !allowedOrigin(c.grant, parsed.Scheme+"://"+parsed.Host) {
			return result, browserError("originDenied", "Navigation destination must be enrolled without credentials", "notDispatched")
		}
		for key := range parsed.Query() {
			if regexp.MustCompile(`(?i)password|token|secret|credential`).MatchString(key) {
				return result, browserError("secretURL", "Navigation URL may not embed credentials", "notDispatched")
			}
		}
	}
	observation, c, d, err := g.observe(ctx, p, surface)
	if err != nil {
		return result, err
	}
	result.Observation = &observation
	command := Command{Action: action, Identity: d.Identity, AttemptID: attemptID}
	if action == "browser.navigate" {
		command.Args = map[string]any{"url": destination}
	}
	reply, err := g.broker.call(ctx, c, command, true, func() error { _, e := g.LeaseEpoch(ctx, p); return e })
	result.DispatchState = reply.DispatchState
	if result.DispatchState == "" {
		result.DispatchState = "notDispatched"
		var detail *model.MechanizeError
		if errors.As(err, &detail) {
			result.DispatchState = detail.DispatchState
		}
	}
	result.Ready, result.Active = reply.Ready, reply.Active
	if reply.NewDocument != nil {
		next := *reply.NewDocument
		if next.ProfileChannel != d.ProfileChannel || next.BrowserInstance != d.BrowserInstance || next.TabID != d.TabID || next.FrameID != 0 || next.DocumentID == "" || next.Generation == 0 || !allowedOrigin(c.grant, next.Origin) {
			result.DispatchState = "unknown"
			return result, browserError("receiptMismatch", "Navigation document receipt scope mismatch", "unknown")
		}
		next.TabHandle = next.QualifiedTabID()
		result.Document = &next
	}
	// Tab readiness/activation is explicit browser state, never business verification.
	return result, err
}
