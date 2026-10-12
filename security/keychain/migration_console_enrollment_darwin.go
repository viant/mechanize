//go:build darwin && cgo

package keychain

import (
	"context"
	"io"
	"os/exec"
	"path/filepath"
	"time"
)

// Execute the existing create-only native enrollment CLI at its final installed
// path. Its signing partition becomes the creator. Credential bytes go through
// a private pipe only after exact runtime and process verification, never argv,
// environment, journals, diagnostics, or a broker/user-visible response.
func enrollUpdatedNativeConsole(ctx context.Context, a *migrationNativeAuthority, app migrationRuntimeArtifact, verify func(context.Context) error) error {
	if a == nil || verify == nil || verify(ctx) != nil || !runtimeRoleRequirement("console", app.NewRequirement) || runtimeVerifyInventory(app.Target, app.New) != nil || !nativeReadinessStatic(app.Target, app.NewRequirement) {
		return errMigrationUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	executable := filepath.Join(app.Target, "Contents/MacOS/MechanizeConsent")
	command := exec.CommandContext(bounded, executable, "--enroll-credential")
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	if home, err := migrationUserHomeDir(); err == nil {
		command.Env = append(command.Env, "HOME="+home)
	}
	input, err := command.StdinPipe()
	if err != nil {
		return errMigrationUnavailable
	}
	defer input.Close()
	output := &readinessOutput{maximum: 4096}
	command.Stdout = output
	command.Stderr = io.Discard
	if command.Start() != nil {
		return errMigrationUnavailable
	}
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
		clear(output.take())
	}()
	system := nativeMigrationReadinessSystem{}
	identity, err := system.inspect(bounded, command.Process.Pid, executable)
	if err != nil || system.verifyProcess(bounded, identity, app.NewRequirement) != nil || verify(bounded) != nil || runtimeVerifyInventory(app.Target, app.New) != nil {
		return errMigrationUnavailable
	}
	if a.withEnrollmentCredential(bounded, func(credential []byte) error {
		if system.verifyProcess(bounded, identity, app.NewRequirement) != nil || verify(bounded) != nil {
			return errMigrationUnavailable
		}
		return migrationWriteAll(input, credential)
	}) != nil {
		return errMigrationUnknown
	}
	if input.Close() != nil {
		return errMigrationUnknown
	}
	err = command.Wait()
	waited = true
	raw := output.take()
	defer clear(raw)
	if err != nil || !migrationEnrollmentSucceeded(raw) || verify(bounded) != nil || !nativeReadinessStatic(app.Target, app.NewRequirement) || runtimeVerifyInventory(app.Target, app.New) != nil {
		return errMigrationUnknown
	}
	return nil
}
