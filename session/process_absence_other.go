//go:build !darwin || !cgo

package session

func listUIDProcesses(uint32) ([]int, error) { return nil, ErrProcessAbsenceUnavailable }

func inspectProcessBirth(int) (ProcessIdentity, bool, error) {
	return ProcessIdentity{}, false, ErrProcessAbsenceUnavailable
}
