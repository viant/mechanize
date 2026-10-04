//go:build !darwin || !cgo

package keychain

import "context"

func supported() error                             { return ErrUnsupported }
func lookup(context.Context, Item) ([]byte, error) { return nil, ErrUnsupported }
