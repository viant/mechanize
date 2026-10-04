package host

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/session"
)

// launchHostOptions builds operator-enrolled providers, never LLM assertions.
// App opening runs through Endly and durable intent, with no input/AX authority.
func launchHostOptions(c Config) (HostOptions, error) {
	if c.NativeLaunch == nil {
		return HostOptions{}, nil
	}
	enrollment := *c.NativeLaunch
	if enrollment.ExpectedUID == nil || *enrollment.ExpectedUID != uint32(os.Getuid()) {
		return HostOptions{}, auth.ErrUnauthorized
	}
	desktopUsers := map[string]bool{}
	for _, user := range c.Users {
		principal, err := auth.NewPrincipal(c.IdentityPolicy.Issuer, user.Tenant, user.Subject, nil)
		if err == nil {
			desktopUsers[principal.Namespace] = user.DesktopAccess
		}
	}
	uid := *enrollment.ExpectedUID
	trust := nativepeer.Options{ExpectedUID: uid, DesignatedRequirement: enrollment.HelperRequirement}
	options := &NativeControlOptions{HelperPath: c.NativeHelper, LockPath: enrollment.LockPath, HelperRequirement: enrollment.HelperRequirement, ExpectedUID: &uid, LaunchOnly: c.NativeLaunch.Mode != "semantic", SemanticOnly: c.NativeLaunch.Mode == "semantic", TargetedKeyboard: enrollment.TargetedKeyboard, SessionKeyboard: enrollment.SessionKeyboard, WindowFrameClick: enrollment.WindowFrameClick}
	options.VerifyExecutable = func(ctx context.Context, path string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return nativepeer.VerifyExecutable(path, trust)
	}
	options.VerifyIdentity = func(ctx context.Context, expected session.ProcessIdentity) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		actual, alive, err := session.InspectProcess(expected.PID)
		if err != nil {
			return err
		}
		if !alive || actual != expected || actual.UID != uid || actual.Executable != c.NativeHelper {
			return ErrNativeControlUnqualified
		}
		return nil
	}
	options.QualifyHelper = func(ctx context.Context, p auth.Principal, identity session.ProcessIdentity, bundles []string, helper NativeControlHelper) (NativeControlReadiness, error) {
		verified, ok := helper.(interface {
			TrustedIdentity() (session.ProcessIdentity, bool)
		})
		if !ok {
			return NativeControlReadiness{}, ErrNativeControlUnqualified
		}
		actual, trusted := verified.TrustedIdentity()
		if !trusted || actual != identity {
			return NativeControlReadiness{}, ErrNativeControlUnqualified
		}
		reply, err := helper.Call(ctx, native.Request{RequestID: "launch-readiness", Method: "doctor", DeadlineRemainingMS: 1000})
		if err != nil {
			return NativeControlReadiness{}, err
		}
		if reply.Error != nil {
			return NativeControlReadiness{}, reply.Error
		}
		var doctor struct {
			BrokerIdentityAuthenticated bool  `json:"brokerIdentityAuthenticated"`
			LaunchEnabled               bool  `json:"launchEnabled"`
			SessionKeyboardEnabled      bool  `json:"sessionKeyboardEnabled"`
			WindowFrameClickEnabled     bool  `json:"windowFrameClickEnabled"`
			CaptureGranted              bool  `json:"captureGranted"`
			TargetedKeyboardEnabled     bool  `json:"targetedKeyboardEnabled"`
			EventPostGranted            bool  `json:"eventPostGranted"`
			SemanticEnabled             bool  `json:"semanticEnabled"`
			AXTrusted                   bool  `json:"axTrusted"`
			SecureInputEnabled          *bool `json:"secureInputEnabled"`
			MutationEnabled             bool  `json:"mutationEnabled"`
			PhysicalFenceEnrolled       bool  `json:"physicalFenceEnrolled"`
			WatchdogLive                bool  `json:"watchdogLive"`
			WindowSession               struct {
				Available bool    `json:"available"`
				OnConsole bool    `json:"onConsole"`
				LoginDone bool    `json:"loginDone"`
				UID       *uint32 `json:"uid"`
			} `json:"windowSession"`
		}
		if json.Unmarshal(reply.Result, &doctor) != nil || !doctor.BrokerIdentityAuthenticated || doctor.MutationEnabled || !doctor.PhysicalFenceEnrolled || !doctor.WatchdogLive || !doctor.WindowSession.Available || !doctor.WindowSession.OnConsole || !doctor.WindowSession.LoginDone || doctor.WindowSession.UID == nil || *doctor.WindowSession.UID != uid {
			return NativeControlReadiness{}, ErrNativeControlUnqualified
		}
		semantic := enrollment.Mode == "semantic"
		if semantic {
			if enrollment.WindowFrameClick && (!doctor.WindowFrameClickEnabled || !doctor.CaptureGranted || !doctor.EventPostGranted) {
				return NativeControlReadiness{}, ErrNativeControlUnqualified
			}
			if (enrollment.TargetedKeyboard && !doctor.TargetedKeyboardEnabled || enrollment.SessionKeyboard && !doctor.SessionKeyboardEnabled) || (enrollment.TargetedKeyboard || enrollment.SessionKeyboard) && !doctor.EventPostGranted {
				return NativeControlReadiness{}, ErrNativeControlUnqualified
			}
			if !doctor.SemanticEnabled || !doctor.AXTrusted || doctor.SecureInputEnabled == nil || *doctor.SecureInputEnabled {
				return NativeControlReadiness{}, ErrNativeControlUnqualified
			}
		} else if !doctor.LaunchEnabled {
			return NativeControlReadiness{}, ErrNativeControlUnqualified
		}
		return NativeControlReadiness{AllApplicationsQualified: len(bundles) == 0 && desktopUsers[p.Namespace], TargetedKeyboardQualified: enrollment.TargetedKeyboard && doctor.TargetedKeyboardEnabled, SessionKeyboardQualified: enrollment.SessionKeyboard && doctor.SessionKeyboardEnabled, WindowFrameClickQualified: enrollment.WindowFrameClick && doctor.WindowFrameClickEnabled && doctor.CaptureGranted, EventPost: doctor.EventPostGranted, SemanticQualified: semantic, Accessibility: semantic, IdentityQualified: true, ActiveGraphicalSession: true, WatchdogLive: true, LaunchQualified: true, QualifiedBundles: append([]string(nil), bundles...), ValidUntil: time.Now().Add(time.Second)}, nil
	}
	return HostOptions{NativeControl: options}, nil
}
