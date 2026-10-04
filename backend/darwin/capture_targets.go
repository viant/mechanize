package darwin

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/model"
	"io"
	"math"
	"time"
)

const MaximumCaptureWindows = 128

type CaptureWindowListOptions struct {
	HelperPath        string
	BundleID          string
	ProcessID         int
	ProcessStartToken string
	Limit             int
	Stderr            io.Writer
}
type CaptureWindowTarget struct {
	BundleID          string        `json:"bundleId"`
	ProcessStartToken string        `json:"processStartToken"`
	PID               int32         `json:"pid"`
	WindowID          uint32        `json:"windowId"`
	Title             string        `json:"title"`
	TitleTruncated    bool          `json:"titleTruncated"`
	Bounds            CaptureBounds `json:"bounds"`
}
type CaptureWindowList struct {
	BundleID   string                `json:"bundleId"`
	Windows    []CaptureWindowTarget `json:"windows"`
	ReturnedAt string                `json:"returnedAt"`
	Truncated  bool                  `json:"truncated"`
}

// ListCaptureWindows obtains physical SCK identities for one exact bundle. This
// transport grants no authority: the host must retain exact observe consent.
func ListCaptureWindows(ctx context.Context, options CaptureWindowListOptions) (result CaptureWindowList, err error) {
	if err := (model.Surface{Kind: "native", ProcessID: options.ProcessID, ProcessStartToken: options.ProcessStartToken}).ValidateProcessIdentity(); err != nil {
		return result, &CaptureError{Cause: err, CleanupConfirmed: true, DispatchState: "notDispatched"}
	}
	if options.HelperPath == "" || options.BundleID == "" || len(options.BundleID) > 512 || options.Limit < 1 || options.Limit > MaximumCaptureWindows {
		return result, &CaptureError{Cause: errors.New("exact bundle and bounded window limit required"), CleanupConfirmed: true, DispatchState: "notDispatched"}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client, err := NewClient(ctx, Options{HelperPath: options.HelperPath, Stderr: options.Stderr})
	if err != nil {
		return result, &CaptureError{Cause: err, CleanupConfirmed: true, DispatchState: "notDispatched"}
	}
	dispatched := false
	defer func() {
		cancel()
		cleanup := client.Close()
		if err != nil || cleanup != nil {
			result = CaptureWindowList{}
			state := "notDispatched"
			if dispatched {
				state = "unknown"
			}
			err = &CaptureError{Cause: errors.Join(err, cleanup), CleanupConfirmed: cleanup == nil, DispatchState: state}
		}
	}()
	doctor, err := client.Call(ctx, Request{RequestID: "capture-windows-doctor", Method: "doctor", DeadlineRemainingMS: 30000})
	if err != nil {
		return result, err
	}
	started := time.Now()
	paramsMap := map[string]any{"bundleId": options.BundleID, "limit": options.Limit}
	if options.ProcessID != 0 {
		paramsMap["processId"] = options.ProcessID
		paramsMap["processStartToken"] = options.ProcessStartToken
	}
	params, _ := json.Marshal(paramsMap)
	dispatched = true
	reply, err := client.Call(ctx, Request{RequestID: "capture-windows", Method: "capture.windows", HelperEpoch: doctor.HelperEpoch, DeadlineRemainingMS: 30000, Params: params})
	if err != nil {
		return result, err
	}
	if err = json.Unmarshal(reply.Result, &result); err != nil {
		return CaptureWindowList{}, err
	}
	if err = validateCaptureWindows(result, options.BundleID, options.Limit, started, time.Now()); err != nil {
		return CaptureWindowList{}, err
	}
	if options.ProcessID != 0 {
		for _, row := range result.Windows {
			if int(row.PID) != options.ProcessID || row.ProcessStartToken != options.ProcessStartToken {
				return CaptureWindowList{}, nativeError("staleReference", "Discovery process fingerprint mismatch")
			}
		}
	}
	return result, nil
}

func validateCaptureWindows(result CaptureWindowList, bundle string, limit int, started, returned time.Time) error {
	stamp, err := time.Parse(time.RFC3339, result.ReturnedAt)
	if err != nil || stamp.Before(started.Add(-time.Second)) || stamp.After(returned.Add(time.Second)) || result.BundleID != bundle || len(result.Windows) > limit || limit < 1 || limit > MaximumCaptureWindows || (result.Truncated && len(result.Windows) != limit) {
		return errors.New("capture window scope, freshness or bound mismatch")
	}
	seen := map[uint32]bool{}
	finite := func(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
	for _, window := range result.Windows {
		b := window.Bounds
		if (model.Surface{Kind: "native", ProcessID: int(window.PID), ProcessStartToken: window.ProcessStartToken}).ValidateProcessIdentity() != nil || window.BundleID != bundle || window.PID <= 0 || window.WindowID == 0 || seen[window.WindowID] || len(window.Title) > 1024 || !finite(b.X) || !finite(b.Y) || !finite(b.Width) || !finite(b.Height) || b.Width <= 0 || b.Height <= 0 {
			return errors.New("invalid or foreign physical capture window")
		}
		seen[window.WindowID] = true
	}
	return nil
}
