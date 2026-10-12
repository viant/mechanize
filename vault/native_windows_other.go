//go:build !darwin || !cgo

package vault

func newNativeWindowProbe(NativeWindowOptions) (nativeWindowProbe, error) { return nil, ErrUnavailable }
