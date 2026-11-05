//go:build !darwin || !cgo

package vault

// Unsupported platforms expose no clipboard delivery implementation.
func NewLocalPasswordClipboard() PasswordPasteClipboard { return nil }
