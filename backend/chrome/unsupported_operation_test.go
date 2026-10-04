package chrome

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

func checkedGuardFixture(t *testing.T) (*Gateway, *Broker, net.Conn, auth.Principal) {
	t.Helper()
	user := principal(t, "checked-guard")
	grant := enrollment(user, "profile-checked-guard")
	broker := fixtureBroker(t, grant)
	conn := connectHost(t, broker, grant)
	publish(t, broker, conn, grant, document(grant, 7))
	gateway, err := NewGateway(broker, GatewayOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return gateway, broker, conn, user
}

func unsupportedReadStep(action, attribute, matcher string, expected *model.Value) model.Step {
	step := model.Step{
		ID:     action + "-guard",
		Action: action,
		Target: model.Selector{
			Surface:     model.Surface{Kind: "web", Origin: fixtureOrigin},
			Locator:     &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "counter"}, Exact: true},
			Cardinality: "one",
		},
		TimeoutMs: 100,
		Effect:    model.Effect{Class: model.ReadOnly},
	}
	if action == "element.read" {
		step.Arguments = map[string]model.Value{"attribute": {Kind: model.StringValue, String: attribute}}
	} else {
		step.Assertion = &model.Assertion{Matcher: matcher, Expected: expected}
	}
	return step
}

func assertNoBrowserCommand(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	defer conn.SetReadDeadline(time.Time{})
	if _, err := ReadFrame(conn); err == nil {
		t.Fatal("unsupported read/assertion reached the Chrome wire")
	} else {
		var networkErr net.Error
		if !errors.As(err, &networkErr) || !networkErr.Timeout() {
			t.Fatalf("unexpected Chrome connection result: %v", err)
		}
	}
}

func TestGatewayRejectsUnsupportedCheckedOperationsBeforeWire(t *testing.T) {
	gateway, broker, conn, user := checkedGuardFixture(t)
	ctx := auth.WithPrincipal(context.Background(), user)
	steps := []struct {
		name string
		step model.Step
		code string
	}{
		{name: "checked read", step: unsupportedReadStep("element.read", "checked", "", nil), code: "unsupportedAttribute"},
		{name: "checked assertion", step: unsupportedReadStep("expect", "", "toBeChecked", nil), code: "unsupportedAssertion"},
		{name: "missing expected value", step: unsupportedReadStep("expect", "", "toHaveValue", nil)},
		{name: "missing expected text", step: unsupportedReadStep("expect", "", "toHaveText", nil)},
	}
	for _, test := range steps {
		t.Run(test.name, func(t *testing.T) {
			result, err := gateway.Execute(ctx, user, test.step, nil)
			if err == nil || result.DispatchState != "notDispatched" {
				t.Fatalf("unsupported operation result=%+v err=%v", result, err)
			}
			if test.code != "" {
				code(t, err, test.code)
			}
			broker.mu.Lock()
			pending := len(broker.channels[channelKey("profile-checked-guard", "browser1")].pending)
			broker.mu.Unlock()
			if pending != 0 {
				t.Fatal("unsupported operation left a browser command pending")
			}
			assertNoBrowserCommand(t, conn)
		})
	}
}
