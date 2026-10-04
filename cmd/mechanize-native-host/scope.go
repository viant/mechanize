package main

import (
	"errors"
	"fmt"

	"github.com/viant/mechanize/auth/nativepeer"
)

// Scope comes only from the fixed private operator configuration. Browser
// messages and signed ancestry cannot silently widen an enrolled profile.
func configuredTrustScope(config *Config) (string, error) {
	if config == nil {
		return "", errors.New("native host trust configuration required")
	}
	switch config.TrustScope {
	case "", "profile":
		return "profile", nil
	case "desktop":
		if config.ProfileDirectory != "" {
			return "", errors.New("desktop browser trust cannot carry a profile directory")
		}
		return "desktop", nil
	default:
		return "", errors.New("unknown browser trust scope")
	}
}

func requireImmediateChromeParent(evidence nativepeer.ChromeProcessEvidence) error {
	if len(evidence.Ancestors) != 1 || evidence.Ancestors[0] != evidence.ChromeParent {
		return errors.New("immediate signed Chrome parent required for browser trust scope")
	}
	return nil
}

// The supplied evidence has already passed own-image and Chrome process/code
// verification. Desktop scope removes only profile-launch qualification.
func qualifyLaunchScope(config *Config, evidence nativepeer.ChromeProcessEvidence, args []string) error {
	scope, err := configuredTrustScope(config)
	if err != nil {
		return err
	}
	config.profileQualified = false
	if config.FixtureEnrollment {
		return nil
	}
	if config.ProcessTrust == nil {
		return errors.New("production browser process policy required")
	}
	if err := requireImmediateChromeParent(evidence); err != nil {
		return err
	}
	if scope == "desktop" {
		return nil
	}
	profile, err := launchProfile(args, config.ProcessTrust.ChromeExecutable, config.ExtensionOrigin)
	if err != nil {
		return fmt.Errorf("Chrome launch profile rejected: %w", err)
	}
	if profile != config.ProfileDirectory {
		return errors.New("Chrome launch profile does not match operator enrollment")
	}
	if err := validateProfileDirectory(profile, config.ProcessTrust.ExpectedUID); err != nil {
		return err
	}
	config.profileQualified = true
	return nil
}
