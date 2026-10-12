package host

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"github.com/viant/mechanize/vault"
)

func TestPrivateChromeOpenExactShapeAndUnavailableProofDeny(t *testing.T) {
	plan, e := script.Compile(`app("com.google.Chrome").open()`)
	if e != nil {
		t.Fatal(e)
	}
	base := plan.Steps[0]
	if !privateChromeOpen(base) {
		t.Fatal("exact Chrome launch rejected")
	}
	for _, mode := range []string{"args", "url", "pid", "birth", "title", "otherApp", "activate", "locator", "ancestor", "window", "read"} {
		step := base
		switch mode {
		case "args":
			step.Arguments = map[string]model.Value{"arguments": {Kind: model.StringValue, String: "private"}}
		case "url":
			step.Target.Surface.Origin = "https://fixture.test"
		case "pid":
			step.Target.Surface.ProcessID = 1
		case "birth":
			step.Target.Surface.ProcessStartToken = "1:2"
		case "title":
			step.Target.Surface.Title = "private"
		case "otherApp":
			step.Target.Surface.BundleID = "com.fixture.app"
		case "activate":
			step.Action = "app.activate"
		case "locator":
			step.Target.Locator = &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "private"}}
		case "ancestor":
			step.Target.Ancestor = &base.Target
		case "window":
			step.Target.Scope.Window = map[string]model.Value{"id": {Kind: model.StringValue, String: "private"}}
		case "read":
			step.Action = "element.read"
		}
		if privateChromeOpen(step) {
			t.Fatal("expanded launch exception", mode)
		}
	}
	h := &Host{durable: &durable.Builder{}}
	if lease, e := h.authorizeChromeOpenAfterSourceAbsence(context.Background(), auth.Principal{}, base); lease != nil || !errors.Is(e, vault.ErrDeliveryProtected) {
		t.Fatal("missing native-entry guard admitted", e)
	}

	if lease, e := h.authorizeNativeControlStep(context.Background(), auth.Principal{}, base); lease != nil || !errors.Is(e, auth.ErrUnauthorized) {
		t.Fatal("missing authenticated enrollment admitted", e)
	}
}

func TestChromeLaunchSourceBirthsRequiresEverySourceAndDeduplicates(t *testing.T) {
	p := auth.Principal{Namespace: "fixture", ClientID: "actor"}
	snapshot := func(id, birth string) durable.CredentialProtection {
		return durable.CredentialProtection{
			Scope:       data.CredentialProtectionScopeRecord{Namespace: p.Namespace, ClientID: p.ClientID, PreparationID: id, Origin: "https://fixture.test", ProfileChannel: "p", BrowserInstance: "b", TabID: 7, DocumentID: id, DocumentGeneration: 1, ChromeStartToken: birth},
			Preparation: data.CredentialPreparationRecord{Namespace: p.Namespace, ClientID: p.ClientID, PreparationID: id, Origin: "https://fixture.test", ProtectionState: "held"},
		}
	}
	scopes := []durable.CredentialProtection{snapshot("a", "123:1"), snapshot("b", "123:1"), snapshot("c", "124:1")}
	original := append([]durable.CredentialProtection(nil), scopes...)
	births, e := chromeLaunchSourceBirths(p, scopes)
	if e != nil || !reflect.DeepEqual(births, []string{"123:1", "124:1"}) {
		t.Fatal("birth dedup", births, e)
	}
	if !reflect.DeepEqual(scopes, original) {
		t.Fatal("launch proof mutated protection")
	}
	for _, mode := range []string{"noSources", "missingBirth", "foreignClient", "missingExactSource", "differentOrigin", "overflow"} {
		values := append([]durable.CredentialProtection(nil), scopes...)
		switch mode {
		case "noSources":
			values = nil
		case "missingBirth":
			values[1].Scope.ChromeStartToken = ""
		case "foreignClient":
			values[1].Preparation.ClientID = "other"
		case "missingExactSource":
			values[1].Scope.DocumentID = ""
		case "differentOrigin":
			values[1].Preparation.Origin = "https://other.test"
		case "overflow":
			values = make([]durable.CredentialProtection, 513)
		}
		if _, e = chromeLaunchSourceBirths(p, values); !errors.Is(e, vault.ErrDeliveryProtected) {
			t.Fatal("incomplete source proof admitted", mode, e)
		}
	}
}
