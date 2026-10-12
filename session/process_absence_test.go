package session

import (
	"context"
	"errors"
	"os"
	"runtime"
	"testing"
)

func TestCompleteProcessBirthAbsenceRejectsMatchesUncertaintyAndDrift(t *testing.T) {
	for _, mode := range []string{"gone", "newChrome", "renamedAlive", "collision", "inaccessible", "missingBirth", "uid", "drift", "transient", "reusedPID"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			birth := "123:456"
			if mode == "missingBirth" {
				birth = ""
			}
			list := func(uint32) ([]int, error) {
				calls++
				if mode == "drift" || mode == "transient" && calls == 2 {
					if calls%2 == 0 {
						return []int{10, 11}, nil
					}
				}
				return []int{10}, nil
			}
			inspect := func(pid int) (ProcessIdentity, bool, error) {
				id := ProcessIdentity{PID: pid, UID: 501, StartToken: "234:567", Executable: "/Chrome"}
				switch mode {
				case "renamedAlive":
					id.StartToken = "123:456"
					id.Executable = "/renamed"
				case "collision":
					id.StartToken = "123:456"
				case "inaccessible":
					return id, false, errors.New("PRIVATE")
				case "uid":
					id.UID = 502
				case "reusedPID":
					id.Executable = "/other"
				}
				return id, true, nil
			}
			e := verifyProcessBirthAbsent(context.Background(), 501, birth, list, inspect)
			success := mode == "gone" || mode == "newChrome" || mode == "transient" || mode == "reusedPID"
			if (e == nil) != success {
				t.Fatal("incorrect complete absence proof", mode, e)
			}
			if calls > 6 {
				t.Fatal("unbounded churn retry")
			}
		})
	}
}
func TestRealCompleteInventoryCanProveImpossibleHistoricalBirthAbsent(t *testing.T) {
	if os.Getenv("MECHANIZE_PROCESS_ABSENCE_FIXTURE") != "1" {
		t.Skip("standalone kernel inventory fixture explicitly enabled")
	}
	if runtime.GOOS != "darwin" {
		t.Skip("libproc kernel metadata is macOS only")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pids, e := listUIDProcesses(uint32(os.Getuid()))
	if e != nil {
		t.Fatal("kernelUIDEnumerationUnavailable")
	}
	failed, exited, mismatch := 0, 0, 0
	for _, pid := range pids {
		id, alive, e := inspectProcessBirth(pid)
		if e != nil {
			failed++
		}
		if !alive {
			exited++
		}
		if alive && id.UID != uint32(os.Getuid()) {
			mismatch++
		}
	}
	t.Logf("ownedPIDs=%d inspectionUnavailable=%d exited=%d uidMismatch=%d", len(pids), failed, exited, mismatch)
	own, alive, e := inspectProcessBirth(os.Getpid())
	if e != nil || !alive {
		t.Fatal("own kernel birth unavailable")
	}
	if VerifyProcessBirthAbsent(ctx, uint32(os.Getuid()), own.StartToken) == nil {
		t.Fatal("alive original kernel birth falsely proved absent")
	}
	if e := VerifyProcessBirthAbsent(ctx, uint32(os.Getuid()), "1:1"); e != nil {
		t.Fatalf("benign complete OS absence probe unavailable: %v", e)
	}
}
