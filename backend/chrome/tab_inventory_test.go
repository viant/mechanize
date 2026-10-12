package chrome

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
)

func TestTabHandleInventoryRetainedPrivateScopeIsMetadataOnly(t *testing.T) {
	f := newReadFixture(t)
	b := f.g.broker
	b.mu.Lock()
	c := b.channels[channelKey("p1", "b1")]
	original := c.documents[0]
	c.documents[0].Title = "PRIVATE_CANARY"
	c.privateInspection = &credentialAdmissionPending{}
	c.privacy = &credentialPrivacyState{}
	b.mu.Unlock()
	result, err := f.g.ListTabHandles(f.ctx, f.p, original.Origin)
	if err != nil || !result.Complete || len(result.Tabs) != 1 || result.Tabs[0].Handle != original.QualifiedTabID() || result.Tabs[0].Origin != original.Origin {
		t.Fatal("protected channel metadata discovery failed", err)
	}
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), "PRIVATE_CANARY") || strings.Contains(string(raw), original.DocumentID) || f.reads.Load() != 0 || f.mutations.Load() != 0 {
		t.Fatal("metadata route accessed or exposed document data")
	}
	b.mu.Lock()
	if c.privateInspection == nil || c.privacy == nil {
		t.Fatal("metadata route changed private state")
	}
	c.scopeQualified = false
	b.mu.Unlock()
	result, err = f.g.ListTabHandles(f.ctx, f.p, original.Origin)
	if err != nil || result.Complete || len(result.Tabs) != 0 {
		t.Fatal("scope revocation published metadata")
	}
}

func TestTabHandleInventoryNeverPublishesUnqualifiedCachedDocuments(t *testing.T) {
	p := principal(t, "tab-inventory")
	grant := enrollment(p, "tabs")
	b := fixtureBroker(t, grant)
	conn := connectHost(t, b, grant)
	defer conn.Close()
	b.mu.Lock()
	c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	c.inventoryComplete = true
	c.documents = []Document{{Identity: Identity{ProfileChannel: grant.ProfileChannel, BrowserInstance: grant.BrowserInstance, TabID: 7, DocumentID: "doc", Generation: 1}, Origin: grant.Origins[0], Title: "private credential payload"}}
	b.mu.Unlock()
	g, _ := NewGateway(b, GatewayOptions{})
	ctx := auth.WithPrincipal(context.Background(), p)
	out, err := g.ListTabHandles(ctx, p, grant.Origins[0])
	if err != nil || out.Complete || len(out.Tabs) != 0 {
		t.Fatal("fixture cached inventory exposed as qualified", err)
	}
	b.mu.Lock()
	c.fixtureOnly = false
	b.mu.Unlock()
	out, err = g.ListTabHandles(ctx, p, grant.Origins[0])
	if err != nil || out.Complete || len(out.Tabs) != 0 {
		t.Fatal("missing process qualification exposed inventory", err)
	}
	if _, err = g.ListTabHandles(ctx, p, "https://fixture.test/path"); err == nil {
		t.Fatal("page path accepted as origin")
	}
	foreign := principal(t, "other-owner")
	out, err = g.ListTabHandles(auth.WithPrincipal(context.Background(), foreign), foreign, grant.Origins[0])
	if err != nil || out.Complete || len(out.Tabs) != 0 {
		t.Fatal("foreign inventory exposed", err)
	}
}
