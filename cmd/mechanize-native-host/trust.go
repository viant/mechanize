package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/viant/mechanize/auth/nativepeer"
)

func defaultConfigPath() (string, error) {
	account, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		return "", err
	}
	return filepath.Join(account.HomeDir, "Library", "Application Support", "Mechanize", "native-host.json"), nil
}
func validatePrivateFile(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("fixed absolute native-host config required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("native-host config unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || stat.Nlink != 1 || (stat.Uid != uint32(os.Getuid()) && stat.Uid != 0) {
		return errors.New("native-host config must be a private owned regular file")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("native-host config must not traverse symlinks")
	}
	return nil
}
func validateBrokerSocket(path string, uid uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("fixed absolute broker socket required")
	}
	resolved, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || resolved != filepath.Dir(path) {
		return errors.New("broker socket parent must be canonical")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return errors.New("broker socket parent must be private")
	}
	owner, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uid {
		return errors.New("broker socket directory owner mismatch")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("broker socket must be private")
	}
	owner, ok = info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uid {
		return errors.New("broker socket owner mismatch")
	}
	return nil
}
func verifyHostProcess(ctx context.Context, config *Config) (nativepeer.ChromeProcessEvidence, error) {
	if config.FixtureEnrollment {
		return nativepeer.ChromeProcessEvidence{}, nil
	}
	if config.ProcessTrust == nil || config.BrokerRequirement == "" {
		return nativepeer.ChromeProcessEvidence{}, errors.New("production signed native-host/Chrome/reverse broker policy required")
	}
	executable, err := os.Executable()
	if err != nil || executable != config.ProcessTrust.NativeHostExecutable {
		return nativepeer.ChromeProcessEvidence{}, errors.New("running native host does not match fixed enrolled executable")
	}
	if err = nativepeer.VerifyExecutable(executable, nativepeer.Options{ExpectedUID: config.ProcessTrust.ExpectedUID, DesignatedRequirement: config.ProcessTrust.NativeHostRequirement}); err != nil {
		return nativepeer.ChromeProcessEvidence{}, err
	}
	if err = nativepeer.VerifyExecutable(config.ProcessTrust.ChromeExecutable, nativepeer.Options{ExpectedUID: config.ProcessTrust.ExpectedUID, DesignatedRequirement: config.ProcessTrust.ChromeRequirement}); err != nil {
		return nativepeer.ChromeProcessEvidence{}, err
	}
	evidence, err := nativepeer.VerifyChromeProcess(ctx, os.Getpid(), *config.ProcessTrust)
	if err != nil {
		return nativepeer.ChromeProcessEvidence{}, err
	}
	if err := requireImmediateChromeParent(evidence); err != nil {
		return nativepeer.ChromeProcessEvidence{}, err
	}
	return evidence, nil
}
func validateEmbeddedBrokerRequirement(config *Config) error {
	if config.FixtureEnrollment {
		return nil
	}
	if strings.TrimSpace(embeddedBrokerRequirement) == "" || strings.ContainsRune(embeddedBrokerRequirement, 0) || config.BrokerRequirement != embeddedBrokerRequirement {
		return errors.New("production broker requirement must exactly match the signed native-host image pin")
	}
	return nil
}
func verifyBrokerPeer(config *Config, broker net.Conn) error {
	if config.FixtureEnrollment {
		return nil
	}
	if err := validateEmbeddedBrokerRequirement(config); err != nil {
		return err
	}
	if config.ProcessTrust == nil {
		return errors.New("reverse broker signing policy unavailable")
	}
	unix, ok := broker.(*net.UnixConn)
	if !ok {
		return errors.New("authenticated Unix broker connection required")
	}
	verify, err := nativepeer.NewVerifier(nativepeer.Options{ExpectedUID: config.ProcessTrust.ExpectedUID, DesignatedRequirement: embeddedBrokerRequirement})
	if err != nil {
		return err
	}
	return verify(unix)
}

// The only credential-loading entry point orders both independent proofs first.
// Injectable functions exist only in this package for inert unit fixtures.
func authenticatedCredential(ctx context.Context, config *Config, broker net.Conn, process func(context.Context, *Config) (nativepeer.ChromeProcessEvidence, error), peer func(*Config, net.Conn) error, load func() (string, error)) (string, error) {
	if _, err := configuredTrustScope(config); err != nil {
		return "", err
	}
	config.processQualified = false
	if err := validateEmbeddedBrokerRequirement(config); err != nil {
		return "", err
	}
	before, err := process(ctx, config)
	if err != nil {
		return "", err
	}
	if err = peer(config, broker); err != nil {
		return "", err
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	credential, err := load()
	if err != nil {
		return "", err
	}
	if err = peer(config, broker); err != nil {
		return "", err
	}
	after, err := process(ctx, config)
	if err != nil {
		return "", err
	}
	if !config.FixtureEnrollment && (before.NativeHost != after.NativeHost || before.ChromeParent != after.ChromeParent) {
		return "", errors.New("native-host/Chrome identity changed while loading enrollment")
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	config.processQualified = !config.FixtureEnrollment
	return credential, nil
}
