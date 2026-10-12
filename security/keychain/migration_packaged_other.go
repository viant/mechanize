//go:build !darwin || !cgo

package keychain

import (
	"context"
	"io"
	"os"
)

func RunPackagedCustodyMigration(_ context.Context, _ string, channel io.ReadWriteCloser, descriptor *os.File) error {
	if channel != nil {
		channel.Close()
	}
	if descriptor != nil {
		descriptor.Close()
	}
	return errMigrationUnavailable
}
