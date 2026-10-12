// Package history reconciles explicitly attributed, read-only payment records.
// It does not calculate tax liabilities, authenticate, or execute payments.
package history

import (
	"errors"
	"math"
	"sort"
	"time"
)

var ErrInvalid = errors.New("invalid payment history input")

// Record contains no banking credentials or account numbers. Period is the tax
// period from transaction details, never inferred from the transaction date.
type Record struct {
	OperationID string `json:"operationID"`
	Subject     string `json:"subject"`
	Period      string `json:"period"`      // YYYY-MM
	Date        string `json:"date"`        // YYYY-MM-DD
	AmountMinor int64  `json:"amountMinor"` // positive payment amount, e.g. grosze
	Status      string `json:"status"`      // completed, pending, scheduled, reversed, failed
}

type Expected struct {
	Subject     string `json:"subject"`
	Period      string `json:"period"`
	AmountMinor int64  `json:"amountMinor"` // independently supplied liability
}

type Balance struct {
	Subject         string   `json:"subject"`
	Period          string   `json:"period"`
	CompletedMinor  int64    `json:"completedMinor"`
	PendingMinor    int64    `json:"pendingMinor"`
	ScheduledMinor  int64    `json:"scheduledMinor"`
	ExpectedMinor   *int64   `json:"expectedMinor,omitempty"`
	DifferenceMinor *int64   `json:"differenceMinor,omitempty"` // expected minus completed
	OperationIDs    []string `json:"operationIDs"`
	Flags           []string `json:"flags"`
}

type Report struct {
	AsOf                    string    `json:"asOf"`
	Balances                []Balance `json:"balances"`
	Unattributed            []Record  `json:"unattributed"`
	ConflictingOperationIDs []string  `json:"conflictingOperationIDs"`
	// This pure evaluator cannot attest that a website/export includes every row.
	Coverage string `json:"coverage"`
}

func validDate(value, layout string) bool {
	parsed, err := time.Parse(layout, value)
	return err == nil && parsed.Format(layout) == value
}

func add(total *int64, value int64) bool {
	if value > math.MaxInt64-*total {
		return false
	}
	*total += value
	return true
}

// Reconcile evaluates observed rows through asOf. Repeated copies of the same
// operation are counted once; contradictory copies are excluded and flagged.
// Unattributed rows cannot silently satisfy a subject/period liability.
func Reconcile(rows []Record, expected []Expected, asOf string) (Report, error) {
	report := Report{AsOf: asOf, Coverage: "unverified", Balances: []Balance{}, Unattributed: []Record{}, ConflictingOperationIDs: []string{}}
	if !validDate(asOf, "2006-01-02") || len(rows) > 100000 || len(expected) > 10000 {
		return Report{}, ErrInvalid
	}
	unique := map[string]Record{}
	conflicts := map[string]bool{}
	for _, row := range rows {
		if row.OperationID == "" || len(row.OperationID) > 256 || len(row.Subject) > 256 || row.AmountMinor <= 0 || !validDate(row.Date, "2006-01-02") || row.Period != "" && !validDate(row.Period, "2006-01") {
			return Report{}, ErrInvalid
		}
		switch row.Status {
		case "completed", "pending", "scheduled", "reversed", "failed":
		default:
			return Report{}, ErrInvalid
		}
		if old, ok := unique[row.OperationID]; ok && old != row {
			conflicts[row.OperationID] = true
		}
		unique[row.OperationID] = row
	}
	type key struct{ subject, period string }
	groups := map[key]*Balance{}
	get := func(k key) *Balance {
		if groups[k] == nil {
			groups[k] = &Balance{Subject: k.subject, Period: k.period, OperationIDs: []string{}, Flags: []string{}}
		}
		return groups[k]
	}
	count := map[key]int{}
	for id, row := range unique {
		if conflicts[id] {
			continue
		}
		if row.Date > asOf && row.Status != "scheduled" {
			continue
		}
		if row.Subject == "" || row.Period == "" {
			report.Unattributed = append(report.Unattributed, row)
			continue
		}
		k := key{row.Subject, row.Period}
		b := get(k)
		b.OperationIDs = append(b.OperationIDs, id)
		switch row.Status {
		case "completed":
			if !add(&b.CompletedMinor, row.AmountMinor) {
				return Report{}, ErrInvalid
			}
			count[k]++
		case "pending":
			if !add(&b.PendingMinor, row.AmountMinor) {
				return Report{}, ErrInvalid
			}
		case "scheduled":
			if !add(&b.ScheduledMinor, row.AmountMinor) {
				return Report{}, ErrInvalid
			}
		case "reversed":
			b.Flags = append(b.Flags, "reversedOperationReview")
		case "failed":
			b.Flags = append(b.Flags, "failedOperationReview")
			// Reversal linkage must be established by the source adapter; no guessed offsets.
		}
	}
	for _, e := range expected {
		if e.Subject == "" || len(e.Subject) > 256 || !validDate(e.Period, "2006-01") || e.AmountMinor < 0 {
			return Report{}, ErrInvalid
		}
		b := get(key{e.Subject, e.Period})
		if b.ExpectedMinor != nil {
			return Report{}, ErrInvalid
		}
		amount := e.AmountMinor
		b.ExpectedMinor = &amount
		difference := amount - b.CompletedMinor
		b.DifferenceMinor = &difference
		if difference > 0 {
			b.Flags = append(b.Flags, "observedShortfallCoverageUnverified")
		}
		if difference < 0 {
			b.Flags = append(b.Flags, "observedExcess")
		}
	}
	for k, b := range groups {
		if count[k] > 1 {
			b.Flags = append(b.Flags, "multipleCompletedOperationsReview")
		}
		if b.PendingMinor > 0 || b.ScheduledMinor > 0 {
			b.Flags = append(b.Flags, "unsettledOperationsReview")
		}
		if b.ExpectedMinor == nil {
			b.Flags = append(b.Flags, "liabilityUnknown")
		}
		sort.Strings(b.OperationIDs)
		sort.Strings(b.Flags)
		report.Balances = append(report.Balances, *b)
	}
	for id := range conflicts {
		report.ConflictingOperationIDs = append(report.ConflictingOperationIDs, id)
	}
	sort.Strings(report.ConflictingOperationIDs)
	sort.Slice(report.Unattributed, func(i, j int) bool { return report.Unattributed[i].OperationID < report.Unattributed[j].OperationID })
	sort.Slice(report.Balances, func(i, j int) bool {
		a, b := report.Balances[i], report.Balances[j]
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		return a.Period < b.Period
	})
	return report, nil
}
