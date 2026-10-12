package chrome

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"strings"
	"testing"
)

func TestControllerSelectorsOnlyInOwnedNativeStatus(t *testing.T) {
	p, err := auth.NewPrincipal("fixture", "", "native-selectors", []string{"desktop:observe", "consent:admin"})
	if err != nil {
		t.Fatal(err)
	}
	other, _ := auth.NewPrincipal("fixture", "", "foreign-selectors", []string{"desktop:observe", "consent:admin"})
	grant := enrollment(p, "native-selectors")
	b := fixtureBroker(t, grant)
	g, _ := NewGateway(b, GatewayOptions{})
	ctx := auth.WithPrincipal(context.Background(), p)
	status, err := g.BrowserStatus(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(status)
	if strings.Contains(string(raw), "profileChannel") || strings.Contains(string(raw), "browserInstance") {
		t.Fatal("non-native status exposed selectors")
	}
	human, err := auth.WithNativeHuman(ctx)
	if err != nil {
		t.Fatal(err)
	}
	status, err = g.BrowserStatus(human, p)
	if err != nil || len(status.Channels) != 1 || status.Channels[0].ProfileChannel != grant.ProfileChannel || status.Channels[0].BrowserInstance != grant.BrowserInstance {
		t.Fatal("owned native selectors unavailable", err)
	}
	foreign, _ := auth.WithNativeHuman(auth.WithPrincipal(context.Background(), other))
	status, err = g.BrowserStatus(foreign, other)
	if err != nil || len(status.Channels) != 0 {
		t.Fatal("foreign native caller saw owned selectors", err)
	}
}
