//go:build !darwin && !linux

package keychain

import "context"

type migrationPreparationAdoption struct{}

func (*migrationPreparationAdoption) check(context.Context, *migrationCoordinator, bool) error {
	return errMigrationUnavailable
}
func (*migrationPreparationAdoption) take(context.Context, *migrationCoordinator, []byte) (string, error) {
	return "", errMigrationUnavailable
}
