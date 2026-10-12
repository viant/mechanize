package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/viant/mechanize/auth"
	"github.com/viant/scy"
	"golang.org/x/sys/unix"
)

var localKeyName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func LocalKeyReference(alias string) (string, error) {
	if !localKeyName.MatchString(alias) {
		return "", ErrUnavailable
	}
	return "mechanize-local-key://native/" + alias, nil
}

// LocalKeyProvisioner is a native-owned Scy key source. Only opaque references
// leave setup; key bytes are resolved inside Cipher and never exposed through MCP.
// The local key is protected by filesystem custody, not macOS Keychain approval.
type LocalKeyProvisioner struct {
	directory, alias, version string
	entropy                   io.Reader
}

func NewLocalKeyProvisioner(directory, alias, version string) (*LocalKeyProvisioner, error) {
	if !outsideGit(directory) || !localKeyName.MatchString(alias) || !localKeyName.MatchString(version) {
		return nil, ErrUnavailable
	}
	current := string(filepath.Separator)
	for _, part := range splitLocalPath(directory) {
		current = filepath.Join(current, part)
		if e := os.Mkdir(current, 0700); e != nil && !os.IsExist(e) {
			return nil, ErrUnavailable
		}
		info, e := os.Lstat(current)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrUnavailable
		}
	}
	p := &LocalKeyProvisioner{directory: directory, alias: alias, version: version, entropy: rand.Reader}
	root, e := p.open()
	if e != nil {
		return nil, e
	}
	root.Close()
	return p, nil
}
func splitLocalPath(path string) []string {
	var parts []string
	for path != "/" && path != "." {
		parts = append(parts, filepath.Base(path))
		path = filepath.Dir(path)
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}
func (p *LocalKeyProvisioner) reference() string { return "mechanize-local-key://native/" + p.alias }
func (p *LocalKeyProvisioner) open() (*os.Root, error) {
	if p == nil || !outsideGit(p.directory) {
		return nil, ErrUnavailable
	}
	for path := p.directory; ; path = filepath.Dir(path) {
		info, e := os.Lstat(path)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrUnavailable
		}
		if path == "/" {
			break
		}
	}
	root, e := os.OpenRoot(p.directory)
	if e != nil {
		return nil, ErrUnavailable
	}
	f, e := root.Open(".")
	if e != nil {
		root.Close()
		return nil, ErrUnavailable
	}
	info, e := f.Stat()
	f.Close()
	if e != nil || !localKeyOwned(info, true) {
		root.Close()
		return nil, ErrUnavailable
	}
	return root, nil
}
func localKeyOwned(info os.FileInfo, directory bool) bool {
	if info == nil {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != uint32(os.Getuid()) {
		return false
	}
	if directory {
		return info.IsDir() && info.Mode().Perm() == 0700 && info.Mode()&os.ModeSymlink == 0
	}
	return info.Mode().IsRegular() && info.Mode().Perm() == 0600 && s.Nlink == 1
}
func localKeyActor(ctx context.Context) bool {
	p, e := auth.FromContext(ctx)
	return e == nil && p.Validate() == nil && ctx.Err() == nil && (auth.NativeHuman(ctx) || p.HasScope("desktop:control"))
}
func (p *LocalKeyProvisioner) read(ctx context.Context, root *os.Root) ([]byte, error) {
	if !localKeyActor(ctx) {
		return nil, ErrUnavailable
	}
	f, e := root.OpenFile(p.alias+".json", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !localKeyOwned(info, false) || info.Size() < 1 || info.Size() > 256 {
		return nil, ErrUnavailable
	}
	material, e := io.ReadAll(io.LimitReader(f, 257))
	defer clear(material)
	if e != nil || len(material) > 256 || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	// Scy consumes the securely opened bytes, rather than reopening a mutable path.
	resource := scy.NewResource("", p.reference(), "")
	resource.Data = material
	secret, e := scy.New().Load(ctx, resource)
	if e != nil {
		return nil, ErrUnavailable
	}
	var value struct {
		Key []byte `json:"key"`
	}
	if e = secret.Decode(&value); e != nil {
		clear(value.Key)
		return nil, ErrUnavailable
	}
	canonical, e := json.Marshal(value)
	defer clear(canonical)
	if e != nil || len(value.Key) != 32 || !bytes.Equal(canonical, material) || ctx.Err() != nil {
		clear(value.Key)
		return nil, ErrUnavailable
	}
	after, e := f.Stat()
	if e != nil || !localKeyOwned(after, false) || !os.SameFile(info, after) || after.Size() != info.Size() {
		clear(value.Key)
		return nil, ErrUnavailable
	}
	return value.Key, nil
}
func (p *LocalKeyProvisioner) Resolve(ctx context.Context, version string) ([]byte, error) {
	if p == nil || version != p.version || !localKeyActor(ctx) {
		return nil, ErrUnavailable
	}
	root, e := p.open()
	if e != nil {
		return nil, ErrUnavailable
	}
	defer root.Close()
	key, e := p.read(ctx, root)
	if e != nil {
		clear(key)
		return nil, ErrUnavailable
	}
	return key, nil
}
func (p *LocalKeyProvisioner) Ready(ctx context.Context) error {
	if p == nil {
		return ErrUnavailable
	}
	if !auth.NativeHuman(ctx) {
		return auth.ErrUnauthorized
	}
	key, e := p.Resolve(ctx, p.version)
	clear(key)
	return e
}
func (p *LocalKeyProvisioner) Ensure(ctx context.Context, canCreate func(context.Context) error) (string, error) {
	if !auth.NativeHuman(ctx) {
		return "", auth.ErrUnauthorized
	}
	if p == nil || canCreate == nil || p.entropy == nil || ctx.Err() != nil {
		return "", ErrUnavailable
	}
	root, e := p.open()
	if e != nil {
		return "", ErrUnavailable
	}
	defer root.Close()
	lock, e := root.OpenFile(".key-write.lock", os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if e != nil {
		return "", ErrUnavailable
	}
	defer lock.Close()
	info, e := lock.Stat()
	if e != nil || !localKeyOwned(info, false) || info.Size() != 0 || unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return "", ErrUnavailable
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	key, e := p.read(ctx, root)
	if e == nil {
		clear(key)
		return p.reference(), nil
	}
	if !os.IsNotExist(e) {
		return "", ErrUnavailable
	}
	if canCreate(ctx) != nil || ctx.Err() != nil {
		return "", ErrUnavailable
	}
	key = make([]byte, 32)
	defer clear(key)
	if _, e = io.ReadFull(p.entropy, key); e != nil {
		return "", ErrUnavailable
	}
	material, e := json.Marshal(struct {
		Key []byte `json:"key"`
	}{key})
	defer clear(material)
	if e != nil {
		return "", ErrUnavailable
	}
	f, e := root.OpenFile(p.alias+".json", os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return "", ErrUnavailable
	}
	_, writeErr := f.Write(material)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || ctx.Err() != nil {
		return "", ErrUnavailable
	}
	directory, e := root.Open(".")
	if e != nil {
		return "", ErrUnavailable
	}
	e = directory.Sync()
	directory.Close()
	if e != nil {
		return "", ErrUnavailable
	}
	actual, e := p.read(ctx, root)
	defer clear(actual)
	if e != nil || subtle.ConstantTimeCompare(actual, key) != 1 || ctx.Err() != nil {
		return "", ErrUnavailable
	}
	return p.reference(), nil
}
