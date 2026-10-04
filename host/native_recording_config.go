package host

import (
	"context"
	"os"
	"path/filepath"

	"github.com/viant/mechanize/auth"
)

func (h *Host) configureNativeRecording(ctx context.Context, c Config, options HostOptions) error {
	var enrolled *NativeRecordingOptions
	if options.NativeRecording != nil {
		copy := *options.NativeRecording
		enrolled = &copy
	} else if c.NativeLaunch != nil {
		enrolled = &NativeRecordingOptions{HelperPath: c.NativeHelper, Requirement: c.NativeLaunch.HelperRequirement, ExpectedUID: c.NativeLaunch.ExpectedUID}
	}
	if enrolled == nil {
		return nil
	}
	if !filepath.IsAbs(c.NativeHelper) || enrolled.HelperPath != c.NativeHelper || enrolled.Requirement == "" || enrolled.ExpectedUID == nil || *enrolled.ExpectedUID != uint32(os.Getuid()) {
		return auth.ErrUnauthorized
	}
	enrolled.Owner = ctx
	enrolled.Revalidate = func(ctx context.Context, p auth.Principal) error {
		user, err := h.authorize(ctx, p)
		if err != nil || !user.DesktopAccess || !user.RecordingAllowed || !p.HasScope("desktop:control") {
			return auth.ErrUnauthorized
		}
		return nil
	}
	manager, err := NewNativeRecordingManager(*enrolled)
	if err != nil {
		return err
	}
	h.nativeRecording = manager
	return nil
}
