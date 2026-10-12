package history

import (
	"math"
	"reflect"
	"testing"
)

func TestPeriodAttributionAndStatuses(t *testing.T) {
	rows := []Record{
		{"op1", "rental-A", "2026-08", "2026-09-12", 18700, "completed"},
		{"op1", "rental-A", "2026-08", "2026-09-12", 18700, "completed"},
		{"op2", "rental-B", "2026-09", "2026-10-02", 18700, "pending"},
		{"op3", "rental-B", "2026-09", "2026-10-03", 18700, "reversed"},
		{"op4", "rental-A", "2026-09", "2026-10-06", 18700, "completed"},
		{"op5", "rental-A", "", "2026-10-01", 18700, "completed"},
		{"op6", "rental-B", "2026-09", "2026-10-20", 18700, "scheduled"},
	}
	r, err := Reconcile(rows, []Expected{{"rental-A", "2026-08", 18700}, {"rental-B", "2026-09", 18700}}, "2026-10-05")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Balances) != 2 || r.Balances[0].CompletedMinor != 18700 || *r.Balances[0].DifferenceMinor != 0 || r.Balances[1].CompletedMinor != 0 || r.Balances[1].PendingMinor != 18700 || r.Balances[1].ScheduledMinor != 18700 || len(r.Unattributed) != 1 || r.Coverage != "unverified" {
		t.Fatalf("unexpected report: %+v", r)
	}
}
func TestConflictingOperationsAndPossibleDuplicates(t *testing.T) {
	rows := []Record{{"conflict", "A", "2026-09", "2026-10-01", 100, "completed"}, {"conflict", "B", "2026-09", "2026-10-01", 100, "completed"}, {"one", "A", "2026-09", "2026-10-01", 100, "completed"}, {"two", "A", "2026-09", "2026-10-01", 100, "completed"}}
	r, err := Reconcile(rows, nil, "2026-10-05")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Balances) != 1 || r.Balances[0].CompletedMinor != 200 || !reflect.DeepEqual(r.ConflictingOperationIDs, []string{"conflict"}) || !reflect.DeepEqual(r.Balances[0].Flags, []string{"liabilityUnknown", "multipleCompletedOperationsReview"}) {
		t.Fatalf("unexpected report: %+v", r)
	}
	// Input order cannot change attribution or totals.
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	other, err := Reconcile(rows, nil, "2026-10-05")
	if err != nil || !reflect.DeepEqual(r, other) {
		t.Fatal("order-dependent reconciliation")
	}
}
func TestInvalidInputAndOverflow(t *testing.T) {
	base := Record{"one", "A", "2026-09", "2026-10-01", 100, "completed"}
	for _, change := range []func(*Record){func(r *Record) { r.Period = "2026-13" }, func(r *Record) { r.Date = "2026-02-30" }, func(r *Record) { r.AmountMinor = -1 }, func(r *Record) { r.Status = "unknown" }, func(r *Record) { r.OperationID = "" }} {
		row := base
		change(&row)
		if _, err := Reconcile([]Record{row}, nil, "2026-10-05"); err != ErrInvalid {
			t.Fatal("invalid row accepted")
		}
	}
	a, b := base, base
	a.AmountMinor = math.MaxInt64
	b.OperationID = "two"
	if _, err := Reconcile([]Record{a, b}, nil, "2026-10-05"); err != ErrInvalid {
		t.Fatal("overflow accepted")
	}
	if _, err := Reconcile(nil, []Expected{{"A", "2026-09", 100}, {"A", "2026-09", 100}}, "2026-10-05"); err != ErrInvalid {
		t.Fatal("duplicate expected liability accepted")
	}
}
