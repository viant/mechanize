//go:build darwin && cgo

package vault

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf16"
)

type appKitPasswordFixture struct {
	input              io.WriteCloser
	output             *bufio.Reader
	pastes             int
	rejectVerification bool
}

func (f *appKitPasswordFixture) call(ctx context.Context, operation string, count int) error {
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	if json.NewEncoder(f.input).Encode(map[string]any{"operation": operation, "count": count}) != nil {
		return ErrUnavailable
	}
	line, err := f.output.ReadString('\n')
	if err != nil || line != "true\n" || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}
func (f *appKitPasswordFixture) CheckEmpty(c context.Context, _ Binding) error {
	return f.call(c, "count", 0)
}
func (f *appKitPasswordFixture) SetProbe(c context.Context, _ Binding) error {
	return f.call(c, "probe", 0)
}
func (f *appKitPasswordFixture) CheckProbe(c context.Context, _ Binding) error {
	return f.call(c, "count", 1)
}
func (f *appKitPasswordFixture) RemoveProbe(c context.Context, _ Binding) error {
	return f.call(c, "removeProbe", 0)
}
func (f *appKitPasswordFixture) PasteOnce(c context.Context, _ Binding) error {
	f.pastes++
	return f.call(c, "paste", 0)
}
func (f *appKitPasswordFixture) Verify(c context.Context, _ Binding, p []byte) error {
	if f.rejectVerification {
		return ErrUnavailable
	}
	return f.call(c, "count", len(utf16.Encode([]rune(string(p)))))
}

// Real encrypted-record delivery and OS pasteboard into an owned NSSecureTextField.
// This does not qualify cross-process AX focus, native host enrollment or login.
func TestPrivatePasswordPasteIntoAppKitSecureField(t *testing.T) {
	if os.Getenv("MECHANIZE_CLIPBOARD_OS_TESTS") != "1" {
		t.Skip("explicit isolated AppKit integration run required")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "private-field")
	if output, err := exec.Command("/usr/bin/swiftc", "testdata/private_password_field.swift", "-o", exe).CombinedOutput(); err != nil {
		t.Fatalf("synthetic fixture compile: %v %s", err, output)
	}
	for _, reject := range []bool{false, true} {
		name := "success"
		if reject {
			name = "verificationFailure"
		}
		t.Run(name, func(t *testing.T) {
			lifetime, stop := context.WithTimeout(context.Background(), 30*time.Second)
			defer stop()
			clipboard := NewLocalPasswordClipboard().(*localPasswordClipboard)
			clipboard.name = "com.viant.mechanize.private-field-test." + filepath.Base(dir) + "." + name
			cmd := exec.CommandContext(lifetime, exe, clipboard.name)
			input, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			output, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				input.Close()
				if err := cmd.Wait(); err != nil {
					t.Error("synthetic fixture did not exit cleanly")
				}
			}()
			target := &appKitPasswordFixture{input: input, output: bufio.NewReader(output), rejectVerification: reject}
			if ready, err := target.output.ReadString('\n'); err != nil || ready != "true\n" {
				t.Fatal("synthetic secure field unavailable")
			}
			_, _, ctx, b, _, delivery := recordDeliveryFixture(t)
			gate := deliveryGate(t)
			lease, err := gate.BeginDelivery(ctx, b, func(context.Context) error { return nil }, func(context.Context) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			manager, err := NewRecordDeliveryManager(delivery, func(_ context.Context, actual Binding) (Binding, error) { return actual, nil })
			if err != nil {
				t.Fatal(err)
			}
			result := PasteRecordPassword(ctx, delivery, manager, lease, b, target, clipboard)
			if result.Verified == reject || !result.CleanupConfirmed || target.pastes != 1 {
				t.Fatal("private delivery/cleanup not confirmed", result)
			}
			if err = target.call(lifetime, "clipboardEmpty", 0); err != nil {
				t.Fatal("owned OS clipboard not empty after delivery")
			}
			_ = PasteRecordPassword(ctx, delivery, manager, lease, b, target, clipboard)
			if target.pastes != 1 {
				t.Fatal("one-shot delivery replayed")
			}
		})
	}
}
