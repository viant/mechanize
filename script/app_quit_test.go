package script

import (
	"github.com/viant/mechanize/model"
	"testing"
)

func TestAppQuitClosedReceiverAndCapability(t *testing.T) {
	for _, source := range []string{`app("com.fixture.app").quit()`, `app("com.fixture.app", processId: 42, processStartToken: "1790000000:1").quit(timeout: 2s)`} {
		plan, err := Compile(source)
		if err != nil {
			t.Fatal(err)
		}
		step := plan.Steps[0]
		if step.Action != "app.quit" || step.Effect.Class != model.ExternalNonIdempotent || len(step.Effect.BusinessKey) == 0 {
			t.Fatalf("unsafe quit %+v", step)
		}
		if err := (Registry{}).CheckCapabilities(plan, map[string]bool{"native:appQuit": true}); err != nil {
			t.Fatal(err)
		}
		if err := (Registry{}).CheckCapabilities(plan, map[string]bool{"native:appActivation": true, "native:appLaunch": true}); err == nil {
			t.Fatal("quit accepted without feature")
		}
	}
	for _, source := range []string{`app("com.fixture.app").getById("x").quit()`, `app("com.fixture.app").window(title: "Test").quit()`, `web.tab(origin: "https://example.test").quit()`, `app("com.fixture.app").quit("force")`, `app("com.fixture.app").quit(force: true)`} {
		if _, err := Compile(source); err == nil {
			t.Fatalf("unsafe quit accepted: %s", source)
		}
	}
}
