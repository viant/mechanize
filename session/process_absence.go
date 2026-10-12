package session

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
)

var ErrProcessAbsenceUnavailable = errors.New("complete process birth absence unavailable")

// VerifyProcessBirthAbsent reads public kernel metadata only. Birth is sourced
// by the host from immutable owned records, never a caller's cleanup assertion.
func VerifyProcessBirthAbsent(ctx context.Context, uid uint32, birth string) error {
	return verifyProcessBirthAbsent(ctx, uid, birth, listUIDProcesses, inspectProcessBirth)
}
func validProcessBirth(v string) bool {
	parts := strings.Split(v, ":")
	if len(parts) != 2 {
		return false
	}
	a, e := strconv.ParseUint(parts[0], 10, 64)
	b, f := strconv.ParseUint(parts[1], 10, 32)
	return e == nil && f == nil && a > 0 && b < 1000000 && strconv.FormatUint(a, 10) == parts[0] && strconv.FormatUint(b, 10) == parts[1]
}
func verifyProcessBirthAbsent(ctx context.Context, uid uint32, birth string, list func(uint32) ([]int, error), inspect ProcessInspector) error {
	if !validProcessBirth(birth) || list == nil || inspect == nil {
		return ErrProcessAbsenceUnavailable
	}
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return ErrProcessAbsenceUnavailable
		}
		pids, e := list(uid)
		if e != nil || len(pids) > 131072 {
			return ErrProcessAbsenceUnavailable
		}
		sort.Ints(pids)
		snapshots := make(map[int]ProcessIdentity)
		stable := true
		for i, pid := range pids {
			if ctx.Err() != nil || pid <= 0 || i > 0 && pids[i-1] == pid {
				return ErrProcessAbsenceUnavailable
			}
			id, alive, e := inspect(pid)
			if e != nil {
				return ErrProcessAbsenceUnavailable
			}
			if !alive {
				snapshots[pid] = ProcessIdentity{}
				continue
			}
			if id.PID != pid || id.UID != uid || !validProcessBirth(id.StartToken) {
				return ErrProcessAbsenceUnavailable
			}
			if id.StartToken == birth {
				return ErrProcessAbsenceUnavailable
			}
			snapshots[pid] = id
		}
		after, e := list(uid)
		if e != nil {
			return ErrProcessAbsenceUnavailable
		}
		sort.Ints(after)
		if len(after) != len(pids) {
			stable = false
		} else {
			for i := range pids {
				if after[i] != pids[i] {
					stable = false
				}
			}
		}
		if !stable {
			continue
		}
		for _, pid := range pids {
			if ctx.Err() != nil {
				return ErrProcessAbsenceUnavailable
			}
			id, alive, e := inspect(pid)
			if e != nil {
				return ErrProcessAbsenceUnavailable
			}
			if alive && id.StartToken == birth {
				return ErrProcessAbsenceUnavailable
			}
			if alive != (snapshots[pid].PID > 0) || alive && id != snapshots[pid] {
				stable = false
			}
		}
		if stable {
			return ctx.Err()
		}
	}
	return ErrProcessAbsenceUnavailable
}
