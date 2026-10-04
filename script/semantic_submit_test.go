package script

import (
	"github.com/viant/mechanize/model"
	"testing"
)

func TestSemanticSubmitIsClosedLocatorMutation(t *testing.T) {
	plan, err := Compile(`app("com.apple.finder").getById("search", exact: true).submit()`)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Steps) != 1 || plan.Steps[0].Action != "element.submit" || plan.Steps[0].Effect.Class != model.ExternalNonIdempotent {
		t.Fatalf("incorrect semantic action %+v", plan)
	}
	for _, source := range []string{`app("com.apple.finder").submit()`, `app("com.apple.finder").getById("search").submit("Return")`, `app("com.apple.finder").getById("search").all(limit: 2).submit()`} {
		if _, err := Compile(source); err == nil {
			t.Fatalf("unsafe submit %s", source)
		}
	}
	if err = (Registry{}).CheckCapabilities(plan, map[string]bool{"native:semanticPress": true, "native:idLocator": true}); err == nil {
		t.Fatal("press capability manufactured submit")
	}
}
