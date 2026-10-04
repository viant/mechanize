//go:build !darwin || !cgo

package nativepeer

func inspectProcessParent(int) (processParent, error) { return processParent{}, ErrUnsupported }
func verifyDynamicProcess(int, string) error          { return ErrUnsupported }
