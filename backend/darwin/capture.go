package darwin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/viant/mechanize/model"
	"image/png"
	"io"
	"math"
	"os"
	"time"
)

const MaximumCaptureBytes = 32 << 20

// WindowCaptureOptions is a low-level transport contract, not authority. The
// gateway must resolve a fresh window in the approved application before calling
// it. Whole-display capture is deliberately excluded from this API.
type WindowCaptureOptions struct {
	HelperPath        string
	BundleID          string
	ProcessStartToken string
	PID               int32
	WindowID          uint32
	MaxBytes          int
	Stderr            io.Writer
}

type CaptureMetadata struct {
	CaptureID         string        `json:"captureId"`
	Nonce             string        `json:"captureNonce"`
	Identity          string        `json:"identity"`
	BundleID          string        `json:"bundleId"`
	PID               int32         `json:"pid"`
	ProcessStartToken string        `json:"processStartToken"`
	WindowID          uint32        `json:"windowId"`
	Width             int           `json:"widthPixels"`
	Height            int           `json:"heightPixels"`
	Bytes             int           `json:"bytes"`
	ReturnedAt        string        `json:"returnedAt"`
	AXAtomic          bool          `json:"axAtomic"`
	Scale             float64       `json:"scale"`
	CoordinateSpace   string        `json:"coordinateSpace"`
	Bounds            CaptureBounds `json:"bounds"`
}

type CaptureBounds struct {
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

type CapturedImage struct {
	Metadata CaptureMetadata
	PNG      []byte
}

// CaptureError distinguishes acknowledgement uncertainty from confirmed helper
// teardown. No bytes are published on an error, even if capture may have occurred.
type CaptureError struct {
	Cause            error
	CleanupConfirmed bool
	DispatchState    string
}

func (e *CaptureError) Error() string { return "native capture failed" }
func (e *CaptureError) Unwrap() error { return e.Cause }

// CaptureWindow uses a disposable read-only helper and a private inherited pipe.
// Keeping each capture on its own pipe/process prevents partial or delayed bytes
// from being reused by another request. No plaintext temporary file is created.
func CaptureWindow(ctx context.Context, options WindowCaptureOptions) (image CapturedImage, err error) {
	if options.ProcessStartToken != "" && !model.ValidProcessStartToken(options.ProcessStartToken) {
		return image, &CaptureError{Cause: errors.New("invalid process fingerprint"), CleanupConfirmed: true, DispatchState: "notDispatched"}
	}
	if options.HelperPath == "" || options.BundleID == "" || options.PID <= 0 || options.WindowID == 0 || options.MaxBytes <= 0 || options.MaxBytes > MaximumCaptureBytes {
		return image, &CaptureError{Cause: errors.New("exact application/PID/window and bounded capture size required"), CleanupConfirmed: true, DispatchState: "notDispatched"}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	reader, writer, err := os.Pipe()
	if err != nil {
		return image, &CaptureError{Cause: err, CleanupConfirmed: true, DispatchState: "notDispatched"}
	}
	defer reader.Close()
	defer writer.Close()
	client, err := NewClient(ctx, Options{HelperPath: options.HelperPath, Artifact: writer, Stderr: options.Stderr})
	if err != nil {
		return image, &CaptureError{Cause: err, CleanupConfirmed: true, DispatchState: "notDispatched"}
	}
	_ = writer.Close() // Only the helper retains the write endpoint.
	dispatched := false
	defer func() {
		cancel()
		_ = reader.Close()
		cleanup := client.Close()
		if err != nil || cleanup != nil {
			image = CapturedImage{}
			state := "notDispatched"
			if dispatched {
				state = "unknown"
			}
			err = &CaptureError{Cause: errors.Join(err, cleanup), CleanupConfirmed: cleanup == nil, DispatchState: state}
		}
	}()
	doctor, err := client.Call(ctx, Request{RequestID: "capture-doctor", Method: "doctor", DeadlineRemainingMS: 30000})
	if err != nil {
		return image, err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return image, err
	}
	nonceText := hex.EncodeToString(nonce[:])
	paramsMap := map[string]any{"artifactFD": 3, "captureNonce": nonceText, "bundleId": options.BundleID, "pid": options.PID, "windowID": options.WindowID, "maxBytes": options.MaxBytes}
	if options.ProcessStartToken != "" {
		paramsMap["processStartToken"] = options.ProcessStartToken
	}
	params, _ := json.Marshal(paramsMap)
	type payloadResult struct {
		data []byte
		err  error
	}
	type callResult struct {
		reply Reply
		err   error
	}
	payload := make(chan payloadResult, 1)
	response := make(chan callResult, 1)
	go func() {
		data, readErr := readCaptureFrame(reader, nonce, options.MaxBytes)
		payload <- payloadResult{data, readErr}
	}()
	dispatched = true
	started := time.Now()
	go func() {
		reply, callErr := client.Call(ctx, Request{RequestID: nonceText, Method: "capture.image", HelperEpoch: doctor.HelperEpoch, DeadlineRemainingMS: 30000, Params: params})
		response <- callResult{reply, callErr}
	}()
	var reply Reply
	for gotBytes, gotReply := false, false; !gotBytes || !gotReply; {
		select {
		case body := <-payload:
			if body.err != nil {
				return CapturedImage{}, body.err
			}
			image.PNG, gotBytes = body.data, true
			payload = nil
		case call := <-response:
			if call.err != nil {
				return CapturedImage{}, call.err
			}
			reply, gotReply = call.reply, true
			response = nil
		case <-ctx.Done():
			return CapturedImage{}, ctx.Err()
		}
	}
	if err = json.Unmarshal(reply.Result, &image.Metadata); err != nil {
		return CapturedImage{}, err
	}
	m := image.Metadata
	finite := func(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
	stamp, stampErr := time.Parse(time.RFC3339, m.ReturnedAt)
	if !model.ValidProcessStartToken(m.ProcessStartToken) || (options.ProcessStartToken != "" && m.ProcessStartToken != options.ProcessStartToken) || m.CaptureID == "" || m.Nonce != nonceText || m.Identity != fmt.Sprintf("window:%d", options.WindowID) || m.BundleID != options.BundleID || m.PID != options.PID || m.WindowID != options.WindowID || m.Bytes != len(image.PNG) || m.Width <= 0 || m.Height <= 0 || m.Width > 32_000_000 || m.Height > 32_000_000 || int64(m.Width)*int64(m.Height) > 32_000_000 || stampErr != nil || stamp.Before(started.Add(-time.Second)) || stamp.After(time.Now().Add(time.Second)) || m.AXAtomic {
		return CapturedImage{}, errors.New("capture scope, size, freshness or evidence identity mismatch")
	}
	if m.CoordinateSpace != "globalLogicalPoints" || !finite(m.Scale) || m.Scale <= 0 || m.Scale > 16 || !finite(m.Bounds.X) || !finite(m.Bounds.Y) || !finite(m.Bounds.Width) || !finite(m.Bounds.Height) || m.Bounds.Width <= 0 || m.Bounds.Height <= 0 || math.Abs(m.Bounds.Width*m.Scale-float64(m.Width)) > 1 || math.Abs(m.Bounds.Height*m.Scale-float64(m.Height)) > 1 {
		return CapturedImage{}, errors.New("capture coordinate mapping invalid")
	}
	config, decodeErr := png.DecodeConfig(bytes.NewReader(image.PNG))
	if decodeErr != nil || config.Width != m.Width || config.Height != m.Height {
		return CapturedImage{}, errors.New("capture PNG dimensions differ from receipt")
	}
	return image, nil
}

func readCaptureFrame(reader io.Reader, expected [16]byte, limit int) ([]byte, error) {
	if limit <= 0 || limit > MaximumCaptureBytes {
		return nil, errors.New("invalid capture byte budget")
	}
	var header [24]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[20:24])
	if string(header[:4]) != "MCAP" || !bytes.Equal(header[4:20], expected[:]) || length == 0 || uint64(length) > uint64(limit) || length > MaximumCaptureBytes {
		return nil, errors.New("capture frame identity or length invalid")
	}
	body := make([]byte, int(length))
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	return body, nil
}
