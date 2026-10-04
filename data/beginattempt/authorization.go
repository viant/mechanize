package beginattempt

import (
	"context"
	"fmt"

	"github.com/viant/mechanize/data"
)

// Init checks the raw scoped graph before native relationship producers copy
// parent links. Explicit foreign claims must fail rather than be normalized.
func (input *BeginAttemptInput) Init(ctx context.Context) error {
	if _, err := data.RequireScope(ctx, input.Namespace); err != nil {
		return err
	}
	if len(input.BeginAttempt) != 1 {
		return fmt.Errorf("one scoped run intent required")
	}
	run := input.BeginAttempt[0]
	if run == nil || run.Id == nil || *run.Id == "" || run.Namespace == nil || *run.Namespace != input.Namespace {
		return fmt.Errorf("explicit scoped run identity required")
	}
	if len(run.Attempts) != 1 {
		return fmt.Errorf("one scoped attempt required")
	}
	attempt := run.Attempts[0]
	if attempt == nil || attempt.Id == nil || *attempt.Id == "" {
		return fmt.Errorf("attempt identity required")
	}
	if err := checkIngressLink(attempt.Namespace, input.Namespace, attempt.Has != nil && attempt.Has.Namespace, true); err != nil {
		return err
	}
	if err := checkIngressLink(attempt.RunId, *run.Id, attempt.Has != nil && attempt.Has.RunId, true); err != nil {
		return err
	}
	if len(attempt.Intents) != 1 || len(attempt.Events) != 1 {
		return fmt.Errorf("one scoped intent and audit event required")
	}
	intent, event := attempt.Intents[0], attempt.Events[0]
	if intent == nil || event == nil {
		return fmt.Errorf("scoped intent and audit event required")
	}
	for _, link := range []struct {
		value            *string
		expected         string
		present, derived bool
	}{
		{intent.Namespace, input.Namespace, intent.Has != nil && intent.Has.Namespace, true},
		{intent.AttemptId, *attempt.Id, intent.Has != nil && intent.Has.AttemptId, true},
		// RunId is not produced by the declared attempt->intent/event links.
		{intent.RunId, *run.Id, intent.Has != nil && intent.Has.RunId, false},
		{event.Namespace, input.Namespace, event.Has != nil && event.Has.Namespace, true},
		{event.AttemptId, *attempt.Id, event.Has != nil && event.Has.AttemptId, true},
		{event.RunId, *run.Id, event.Has != nil && event.Has.RunId, false},
	} {
		if err := checkIngressLink(link.value, link.expected, link.present, link.derived); err != nil {
			return err
		}
	}
	return nil
}

func checkIngressLink(value *string, expected string, present, derived bool) error {
	if value == nil {
		if present || !derived {
			return fmt.Errorf("explicit or required intent relationship is missing")
		}
		return nil // a declared authoritative parent producer supplies this link
	}
	if *value != expected {
		return fmt.Errorf("explicit intent relationship differs from verified parent scope")
	}
	return nil
}
