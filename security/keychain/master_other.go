//go:build !darwin || !cgo

package keychain

func newMasterKeyStore(MasterKeyOptions) (masterKeyStore, error) { return nil, ErrUnsupported }
