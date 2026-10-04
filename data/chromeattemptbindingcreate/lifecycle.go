package chromeattemptbindingcreate

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/data"
	h "github.com/viant/xdatly/handler"
	"reflect"
)

type BindingLifecycle struct{}

func BindingLifecycleDatlyType() reflect.Type { return reflect.TypeOf((*BindingLifecycle)(nil)).Elem() }

var BindingLifecycleHooks = new(BindingLifecycle)
var BindingLifecycleDatly = BindingLifecycleDatlyType()

func (*BindingLifecycle) Init(context.Context, *Binding, h.LifecycleContext[Binding, h.NoParent, CreateChromeAttemptBindingOutput]) error {
	return nil
}
func (*BindingLifecycle) Validate(ctx context.Context, b *Binding, state h.LifecycleContext[Binding, h.NoParent, CreateChromeAttemptBindingOutput]) error {
	a, err := data.RequireChromeAttemptBindingAuthority(ctx)
	if err != nil {
		return err
	}
	if b == nil || state.Previous != nil {
		return errors.New("binding is immutable insert-only; adopt exact generated readback")
	}
	expectedRaw, _ := json.Marshal(a)
	actualRaw, _ := json.Marshal(b)
	var expected, actual map[string]json.RawMessage
	_ = json.Unmarshal(expectedRaw, &expected)
	_ = json.Unmarshal(actualRaw, &actual)
	for key, value := range expected {
		if string(actual[key]) != string(value) {
			return errors.New("binding differs from sealed committed-intent authority")
		}
	}
	if b.Scopes != nil || b.Attempt != nil || b.Run != nil || b.Plan != nil || len(b.IntentEvent) != 0 {
		return errors.New("caller-supplied auxiliary intent facts forbidden")
	}
	return nil
}
func (*BindingLifecycle) AfterSequence(context.Context, *Binding, h.LifecycleContext[Binding, h.NoParent, CreateChromeAttemptBindingOutput]) error {
	return nil
}
func (*BindingLifecycle) AfterQueue(context.Context, *Binding, h.LifecycleContext[Binding, h.NoParent, CreateChromeAttemptBindingOutput]) error {
	return nil
}
func (*BindingLifecycle) Finalize(context.Context, *CreateChromeAttemptBindingInput, *CreateChromeAttemptBindingOutput, h.Outcome) error {
	return nil
}
