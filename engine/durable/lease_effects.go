package durable

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/viant/datly/bootstrap/connector"
	"github.com/viant/datly/standalone"
	"github.com/viant/datly/standalone/config"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/leaseeffects"
)

// LeaseUseEvidence answers only whether any mutation attempt exists for this
// exact namespace and physical lease generation. IntentsPresent means one or
// more; LIMIT 1 is not an exact total count. CountKnown certifies this zero/nonzero
// decision, never helper stop or input release. Every mutation commits its attempt
// before dispatch; read-only steps do not create attempts.
type LeaseUseEvidence struct {
	Namespace      string    `json:"namespace"`
	LeaseEpoch     int       `json:"leaseEpoch"`
	CountKnown     bool      `json:"countKnown"`
	IntentsPresent bool      `json:"intentsPresent"`
	ObservedAt     time.Time `json:"observedAt"`
}

// LeaseUse opens only the already-existing user's database in SQLite read-only
// mode. It deliberately does not call bound/Provision: creating a missing DB or
// schema would manufacture a false zero-intent cleanup proof.
func (b *Builder) LeaseUse(ctx context.Context, p auth.Principal, epoch int) (LeaseUseEvidence, error) {
	evidence := LeaseUseEvidence{Namespace: p.Namespace, LeaseEpoch: epoch}
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
		return evidence, auth.ErrUnauthorized
	}
	if epoch <= 0 {
		return evidence, errors.New("positive physical lease generation required")
	}
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return evidence, errors.New("durable host closed")
	}
	ctx, err = data.WithScope(ctx, data.Scope{Namespace: p.Namespace, LeaseEpoch: epoch})
	if err != nil {
		return evidence, err
	}
	path, info, err := existingLeaseDatabase(b.options.StorageRoot, p.Namespace)
	if err != nil {
		return evidence, err
	}
	const pkg = "github.com/viant/mechanize/data/leaseeffects"
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&_query_only=true&_foreign_keys=on&_busy_timeout=5000"}).String()
	server, err := standalone.New(ctx, standalone.Options{Config: &config.Config{BaseDir: b.options.SourceRoot, Connector: "user", Connectors: []connector.Config{{Name: "user", Driver: "sqlite3", DSN: dsn, MaxOpenConns: 1, MaxIdleConns: 1}}, GoBootstrap: &config.Packages{Packages: []string{pkg}}}, Holders: []any{leaseeffects.LeaseEffectsComponent{}}})
	if err != nil {
		return evidence, err
	}
	defer server.Shutdown(context.Background())
	if err = server.Reload(ctx, 1); err != nil {
		return evidence, err
	}
	input := &leaseeffects.LeaseEffectsInput{}
	input.SetNamespace(p.Namespace)
	input.SetLeaseEpoch(epoch)
	value, err := invoke(ctx, server, "leaseeffects", "LeaseEffects", "GET", input, false)
	if err != nil {
		return evidence, err
	}
	output, ok := value.(*leaseeffects.LeaseEffectsOutput)
	if !ok || output == nil || len(output.Data) > 1 {
		return evidence, errors.New("incomplete or unexpected lease use projection")
	}
	for _, row := range output.Data {
		if row == nil || row.Namespace == nil || *row.Namespace != p.Namespace || row.Id == nil || *row.Id == "" || row.LeaseEpoch == nil || *row.LeaseEpoch != epoch {
			return evidence, errors.New("lease use source identity mismatch")
		}
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, after) {
		return evidence, errors.New("lease use database replaced during read")
	}
	if err = ctx.Err(); err != nil {
		return evidence, err
	}
	evidence.CountKnown = true
	evidence.IntentsPresent = len(output.Data) != 0
	evidence.ObservedAt = time.Now().UTC()
	return evidence, nil
}

func existingLeaseDatabase(root, namespace string) (string, os.FileInfo, error) {
	if !filepath.IsAbs(root) {
		return "", nil, errors.New("absolute trusted storage root required")
	}
	path := filepath.Join(root, "users", namespace, "state.sqlite")
	for _, candidate := range []string{root, filepath.Join(root, "users"), filepath.Join(root, "users", namespace), path} {
		info, err := os.Lstat(candidate)
		if err != nil {
			return "", nil, fmt.Errorf("existing durable lease source unavailable: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", nil, errors.New("lease source symlink rejected")
		}
		if candidate != path && !info.IsDir() {
			return "", nil, errors.New("lease source directory invalid")
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 100 {
		return "", nil, errors.New("existing lease database invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer file.Close()
	var header [16]byte
	if _, err = io.ReadFull(file, header[:]); err != nil || string(header[:]) != "SQLite format 3\x00" {
		return "", nil, errors.New("lease source is not an existing SQLite database")
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", nil, errors.New("lease source changed before read")
	}
	return path, info, nil
}
