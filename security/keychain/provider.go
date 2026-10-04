// Package keychain supplies a read-only, explicitly enrolled Scy/AFS resource
// provider for macOS generic-password items. It never changes Keychain access.
package keychain

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/viant/afs"
	"github.com/viant/afs/storage"
)

const Scheme = "mechanize-keychain"

var (
	ErrUnsupported = errors.New("Keychain lookup requires macOS with cgo")
	ErrReadOnly    = errors.New("Keychain resource provider is read only")
	ErrReference   = errors.New("untrusted or invalid Keychain resource reference")
	registerMu     sync.Mutex
	namePattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

type Item struct {
	Service string
	Account string
}
type Options struct{ Items map[string]Item }

// Reference returns the exact URL accepted for a trusted configuration alias.
// Neither service nor account can be selected by the requesting transport.
func Reference(name string) (string, error) {
	if !namePattern.MatchString(name) {
		return "", ErrReference
	}
	return Scheme + "://generic-password/" + name, nil
}

func parseReference(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != Scheme || u.Host != "generic-password" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.ForceQuery {
		return "", ErrReference
	}
	name := strings.TrimPrefix(u.Path, "/")
	exact, err := Reference(name)
	if err != nil || raw != exact {
		return "", ErrReference
	}
	return name, nil
}

// Register enrolls the trusted alias map using AFS's public provider registry.
// Scy.New().Load(ctx, scy.NewResource("", Reference(name), "")) subsequently
// resolves through this provider. Re-registration fails to preserve enrollment.
func Register(o Options) error {
	if err := supported(); err != nil {
		return err
	}
	m, err := newManager(o, lookup)
	if err != nil {
		return err
	}
	registerMu.Lock()
	defer registerMu.Unlock()
	if _, err = afs.GetRegistry().Get(Scheme); err == nil {
		return errors.New("Keychain resource provider already registered")
	}
	afs.GetRegistry().Register(Scheme, func(options ...storage.Option) (storage.Manager, error) {
		if len(options) != 0 {
			return nil, ErrReference
		}
		return m, nil
	})
	return nil
}

type manager struct {
	items  map[string]Item
	lookup func(context.Context, Item) ([]byte, error)
}

func newManager(o Options, read func(context.Context, Item) ([]byte, error)) (*manager, error) {
	if len(o.Items) == 0 || read == nil {
		return nil, ErrReference
	}
	m := &manager{items: make(map[string]Item, len(o.Items)), lookup: read}
	for name, item := range o.Items {
		if !namePattern.MatchString(name) || strings.TrimSpace(item.Service) == "" || strings.TrimSpace(item.Account) == "" || strings.ContainsRune(item.Service, 0) || strings.ContainsRune(item.Account, 0) {
			return nil, ErrReference
		}
		m.items[name] = item
	}
	return m, nil
}

func (m *manager) Scheme() string { return Scheme }
func (m *manager) Close() error   { return nil }
func (m *manager) OpenURL(ctx context.Context, raw string, options ...storage.Option) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(options) != 0 {
		return nil, ErrReference
	}
	name, err := parseReference(raw)
	if err != nil {
		return nil, err
	}
	item, ok := m.items[name]
	if !ok {
		return nil, ErrReference
	}
	payload, err := m.lookup(ctx, item)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(payload)), nil
}
func (m *manager) Open(ctx context.Context, object storage.Object, options ...storage.Option) (io.ReadCloser, error) {
	if object == nil {
		return nil, ErrReference
	}
	return m.OpenURL(ctx, object.URL(), options...)
}
func (*manager) List(context.Context, string, ...storage.Option) ([]storage.Object, error) {
	return nil, ErrReadOnly
}
func (*manager) Upload(context.Context, string, os.FileMode, io.Reader, ...storage.Option) error {
	return ErrReadOnly
}
func (*manager) Create(context.Context, string, os.FileMode, bool, ...storage.Option) error {
	return ErrReadOnly
}
func (*manager) Delete(context.Context, string, ...storage.Option) error { return ErrReadOnly }

var _ storage.Manager = (*manager)(nil)
