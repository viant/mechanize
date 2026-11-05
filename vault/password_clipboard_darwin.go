//go:build darwin && cgo

package vault

/*
#cgo LDFLAGS: -framework AppKit -framework Foundation
#include <stdlib.h>
int mechanize_password_clipboard_stage(const char *, const char *, const void *, size_t, long long *);
int mechanize_password_clipboard_owned(const char *, const char *, long long);
int mechanize_password_clipboard_clear(const char *, const char *, long long);
*/
import "C"

import (
	"context"
	"sync"
	"time"
	"unicode/utf8"
	"unsafe"
)

type passwordClipboardEntry struct {
	revision C.longlong
	timer    *time.Timer
}
type localPasswordClipboard struct {
	mu       sync.Mutex
	name     string
	entries  map[string]*passwordClipboardEntry
	finished map[string]bool
}

// NewLocalPasswordClipboard provides a write-only private clipboard driver.
// Creating it grants no recipient permission and reads no existing clipboard.
// Use only inside a qualified private delivery lease. The OS clipboard is shared
// with local processes; current-host-only and concealment are not access control.
func NewLocalPasswordClipboard() PasswordPasteClipboard {
	return &localPasswordClipboard{entries: map[string]*passwordClipboardEntry{}, finished: map[string]bool{}}
}
func (c *localPasswordClipboard) Stage(ctx context.Context, token string, value []byte, expires time.Time) error {
	if c == nil || ctx.Err() != nil || !nativeRevision(token) || len(value) == 0 || len(value) > maxCredentialBytes || !utf8.Valid(value) || !expires.After(time.Now()) || expires.After(time.Now().Add(5*time.Second)) {
		return ErrUnavailable
	}
	for _, b := range value {
		if b == 0 {
			return ErrUnavailable
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil || !expires.After(time.Now()) {
		return ErrUnavailable
	}
	if len(c.entries) != 0 || c.finished[token] || len(c.finished) >= 256 {
		return ErrBusy
	}
	e := &passwordClipboardEntry{revision: -1}
	c.entries[token] = e
	// Register cleanup before any OS write. This timer never retains plaintext.
	e.timer = time.AfterFunc(time.Until(expires), func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = c.Clear(cleanup, token)
	})
	name, key := C.CString(c.name), C.CString(token)
	defer C.free(unsafe.Pointer(name))
	defer C.free(unsafe.Pointer(key))
	status := C.mechanize_password_clipboard_stage(name, key, unsafe.Pointer(&value[0]), C.size_t(len(value)), &e.revision)
	if status != 1 || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}
func (c *localPasswordClipboard) VerifyOwnership(ctx context.Context, token string) error {
	if c == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[token]
	if e == nil {
		return ErrUnavailable
	}
	name, key := C.CString(c.name), C.CString(token)
	defer C.free(unsafe.Pointer(name))
	defer C.free(unsafe.Pointer(key))
	if C.mechanize_password_clipboard_owned(name, key, e.revision) != 1 || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}
func (c *localPasswordClipboard) Clear(ctx context.Context, token string) error {
	if c == nil || ctx.Err() != nil || !nativeRevision(token) {
		return ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[token]
	if e == nil {
		if c.finished[token] {
			return nil
		}
		return ErrUnavailable
	}
	name, key := C.CString(c.name), C.CString(token)
	defer C.free(unsafe.Pointer(name))
	defer C.free(unsafe.Pointer(key))
	status := C.mechanize_password_clipboard_clear(name, key, e.revision)
	if status < 1 || ctx.Err() != nil {
		return ErrUnavailable
	}
	if e.timer != nil {
		e.timer.Stop()
	}
	delete(c.entries, token)
	c.finished[token] = true
	return nil
}
