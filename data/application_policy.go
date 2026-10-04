package data

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"unicode/utf8"
)

const ApplicationPolicyID = "application_access"

type ApplicationPolicy struct {
	DesktopWide  bool                    `json:"desktopWide"`
	Applications []ApplicationPolicyRule `json:"applications"`
}
type ApplicationPolicyRule struct {
	BundleID    string   `json:"bundleID"`
	DisplayName string   `json:"displayName"`
	Modes       []string `json:"modes"`
}

var applicationBundleID = regexp.MustCompile(`^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$`)

// CanonicalApplicationPolicy validates exact application identities and returns a
// detached, ordered representation suitable for durable authorization comparison.
func CanonicalApplicationPolicy(p ApplicationPolicy) (ApplicationPolicy, error) {
	if len(p.Applications) > 256 {
		return ApplicationPolicy{}, fmt.Errorf("at most 256 application rules allowed")
	}
	result := ApplicationPolicy{DesktopWide: p.DesktopWide, Applications: make([]ApplicationPolicyRule, 0, len(p.Applications))}
	ids := map[string]bool{}
	for _, rule := range p.Applications {
		if !applicationBundleID.MatchString(rule.BundleID) || len(rule.BundleID) > 255 || ids[rule.BundleID] {
			return ApplicationPolicy{}, fmt.Errorf("invalid or duplicate exact application bundle ID")
		}
		if !utf8.ValidString(rule.DisplayName) || len(rule.DisplayName) > 512 {
			return ApplicationPolicy{}, fmt.Errorf("application display name exceeds 512 bytes or is invalid UTF-8")
		}
		ids[rule.BundleID] = true
		copy := rule
		copy.Modes = make([]string, 0, len(rule.Modes))
		modes := map[string]bool{}
		for _, mode := range rule.Modes {
			if (mode != "observe" && mode != "control" && mode != "record") || modes[mode] {
				return ApplicationPolicy{}, fmt.Errorf("invalid or duplicate application mode")
			}
			modes[mode] = true
			copy.Modes = append(copy.Modes, mode)
		}
		sort.Strings(copy.Modes)
		result.Applications = append(result.Applications, copy)
	}
	sort.Slice(result.Applications, func(i, j int) bool { return result.Applications[i].BundleID < result.Applications[j].BundleID })
	return result, nil
}
func ApplicationPolicyJSON(p ApplicationPolicy) (string, error) {
	p, err := CanonicalApplicationPolicy(p)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(p)
	return string(b), err
}
func (p ApplicationPolicy) Allows(bundleID, mode string) bool {
	if !applicationBundleID.MatchString(bundleID) || (mode != "observe" && mode != "control" && mode != "record") {
		return false
	}
	for _, rule := range p.Applications {
		if rule.BundleID == bundleID {
			for _, m := range rule.Modes {
				if m == mode {
					return true
				}
			}
			return false
		}
	}
	return p.DesktopWide
}
