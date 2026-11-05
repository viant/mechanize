//go:build darwin && cgo

package vault

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Explicit OS integration test uses only an isolated named pasteboard and
// synthetic data. The subprocess returns exit status, never clipboard content.
func TestPasswordClipboardMacOSPrivateLifecycle(t *testing.T) {
	if os.Getenv("MECHANIZE_CLIPBOARD_OS_TESTS") != "1" {
		t.Skip("requires explicit macOS pasteboard integration run")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "check.swift")
	exe := filepath.Join(dir, "check")
	script := `import AppKit
let p=NSPasteboard(name:NSPasteboard.Name(CommandLine.arguments[1]))
switch CommandLine.arguments[2] {
case "value": precondition(p.string(forType:.string)=="synthetic-paste-fixture")
case "empty": precondition(p.types?.isEmpty == true)
case "replace": p.clearContents(); precondition(p.setString("new-user-item",forType:.string))
case "preserved": precondition(p.string(forType:.string)=="new-user-item");p.clearContents()
default: fatalError("unknown fixture command")
}`
	if err := os.WriteFile(source, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("/usr/bin/swiftc", source, "-o", exe).CombinedOutput(); err != nil {
		t.Fatalf("fixture compile: %v %s", err, output)
	}
	for _, mode := range []string{"immediate", "expires", "replacement"} {
		t.Run(mode, func(t *testing.T) {
			c := NewLocalPasswordClipboard().(*localPasswordClipboard)
			c.name = "com.viant.mechanize.clipboard-test." + filepath.Base(dir) + "." + mode
			check := func(command string) {
				t.Helper()
				if err := exec.Command(exe, c.name, command).Run(); err != nil {
					t.Fatalf("clipboard fixture %s failed: %v", command, err)
				}
			}
			ctx := context.Background()
			token := strings.Repeat("a", 64)
			ttl := 4 * time.Second
			if mode == "expires" {
				ttl = 350 * time.Millisecond
			}
			if err := c.Stage(ctx, token, []byte("synthetic-paste-fixture"), time.Now().Add(ttl)); err != nil {
				t.Fatal("stage unavailable", err)
			}
			defer c.Clear(ctx, token)
			if mode != "expires" {
				check("value")
				if c.VerifyOwnership(ctx, token) != nil {
					t.Fatal("ownership missing")
				}
			}
			if mode == "replacement" {
				check("replace")
				if c.VerifyOwnership(ctx, token) == nil {
					t.Fatal("foreign clipboard admitted")
				}
			}
			if mode == "expires" {
				deadline := time.Now().Add(2 * time.Second)
				for time.Now().Before(deadline) {
					c.mu.Lock()
					done := c.finished[token]
					c.mu.Unlock()
					if done {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				c.mu.Lock()
				expired := c.finished[token]
				c.mu.Unlock()
				if !expired {
					t.Fatal("expiration watchdog did not clear the clipboard")
				}
				check("empty")
			}
			if err := c.Clear(ctx, token); err != nil {
				t.Fatal("cleanup unavailable", err)
			}
			if c.VerifyOwnership(ctx, token) == nil {
				t.Fatal("cleared item still authorized paste")
			}
			if mode == "replacement" {
				check("preserved")
			} else {
				check("empty")
			}
		})
	}
}
