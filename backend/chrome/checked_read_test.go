package chrome

import (
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"testing"
)

func TestCheckedReadAndPinnedProofRequireExplicitBoolean(t *testing.T) {
	for _, mode := range []int64{0, 1, 2, 3} {
		f := newReadFixture(t)
		f.p.Scopes = []string{"desktop:observe"}
		f.ctx = auth.WithPrincipal(f.ctx, f.p)
		f.checkedReply.Store(mode)
		step := unsupportedReadStep("element.read", "checked", "", nil)
		step.Target = readTarget()
		step.TimeoutMs = 1000
		result, err := f.g.Execute(f.ctx, f.p, step, nil)
		valid := mode == 1 || mode == 2
		if valid {
			if err != nil || result.Value == nil || result.Value.Kind != model.BoolValue || result.Value.Bool != (mode == 2) {
				t.Fatalf("checked result lost boolean: %+v %v", result, err)
			}
		} else if err == nil || result.Value != nil {
			t.Fatal("missing/contradictory checked state accepted")
		}
		pin, err := f.g.PinReadDocument(f.ctx, f.p, readTarget().Surface)
		if err != nil {
			t.Fatal(err)
		}
		value, proof, err := f.g.ReadPinned(f.ctx, f.p, pin, readTarget(), "checked", nil)
		if valid {
			if err != nil || value.Kind != model.BoolValue || value.Bool != (mode == 2) || proof.RequestID == "" {
				t.Fatalf("checked proof lost authority: %+v %v", value, err)
			}
		} else if err == nil || value.Kind != "" || proof.RequestID != "" {
			t.Fatal("unavailable checked state became proof")
		}
		if f.mutations.Load() != 0 || f.acquireCalls.Load() != 0 {
			t.Fatal("checked read acquired input authority")
		}
	}
}

func TestCheckedAssertionsNeverTreatMissingAsUnchecked(t *testing.T) {
	for _, mode := range []int64{0, 1, 2, 3} {
		for _, negate := range []bool{false, true} {
			f := newReadFixture(t)
			f.checkedReply.Store(mode)
			step := unsupportedReadStep("expect", "", "toBeChecked", nil)
			step.Target = readTarget()
			step.TimeoutMs = 1000
			step.Assertion.Not = negate
			_, err := f.g.Execute(f.ctx, f.p, step, nil)
			wantSuccess := (mode == 1 && negate) || (mode == 2 && !negate)
			if (err == nil) != wantSuccess {
				t.Fatalf("mode=%d not=%v err=%v", mode, negate, err)
			}
			if f.mutations.Load() != 0 {
				t.Fatal("assertion mutated page")
			}
		}
	}
}

func TestPinnedCheckedReadRejectsChangedDocument(t *testing.T) {
	f := newReadFixture(t)
	f.checkedReply.Store(2)
	pin, err := f.g.PinReadDocument(f.ctx, f.p, readTarget().Surface)
	if err != nil {
		t.Fatal(err)
	}
	f.wrongDocument.Store(true)
	value, proof, err := f.g.ReadPinned(f.ctx, f.p, pin, readTarget(), "checked", nil)
	if err == nil || value.Kind != "" || proof.RequestID != "" {
		t.Fatal("foreign document checked state accepted")
	}
}
