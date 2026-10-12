package host

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

type RuntimeSettings struct {
	Transport       string `json:"transport"`
	CurrentAddress  string `json:"currentAddress"`
	CurrentPort     int    `json:"currentPort"`
	SavedPort       int    `json:"savedPort"`
	Revision        int    `json:"revision"`
	RestartRequired bool   `json:"restartRequired"`
}
type runtimePort struct {
	Port     int `json:"port"`
	Revision int `json:"revision"`
}

var errRuntimeSettings = errors.New("local MCP settings unavailable or changed; refresh before saving")

func loopbackPort(address string) (string, int, error) {
	host, raw, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, errRuntimeSettings
	}
	ip := net.ParseIP(host)
	port, err := strconv.Atoi(raw)
	if ip == nil || !ip.IsLoopback() || err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != raw {
		return "", 0, errRuntimeSettings
	}
	return host, port, nil
}
func settingsFileSafe(info os.FileInfo) bool {
	owner, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode().Perm()&0077 == 0 && owner.Uid == uint32(os.Getuid()) && owner.Nlink == 1
}
func openSettingsRoot(path string) (*os.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errRuntimeSettings
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	if resolved != path {
		return nil, errRuntimeSettings
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm()&0077 != 0 || owner.Uid != uint32(os.Getuid()) {
		return nil, errRuntimeSettings
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, errRuntimeSettings
	}
	actual, err := root.Stat(".")
	if err != nil || !os.SameFile(info, actual) {
		root.Close()
		return nil, errRuntimeSettings
	}
	return root, nil
}
func readRuntimePort(root *os.Root) (runtimePort, error) {
	f, err := root.OpenFile(".mcp-port.json", os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return runtimePort{}, nil
	}
	if err != nil {
		return runtimePort{}, errRuntimeSettings
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !settingsFileSafe(info) || info.Size() > 256 {
		return runtimePort{}, errRuntimeSettings
	}
	data, err := io.ReadAll(io.LimitReader(f, 257))
	if err != nil {
		return runtimePort{}, errRuntimeSettings
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var saved runtimePort
	if decoder.Decode(&saved) != nil || decoder.Decode(new(any)) != io.EOF || saved.Port < 1 || saved.Port > 65535 || saved.Revision < 1 {
		return runtimePort{}, errRuntimeSettings
	}
	return saved, nil
}

// LoadRuntimeListen selects a public port override only for an existing HTTP
// launch. Stdio stays stdio. Authentication, host IP and credentials are unchanged.
func LoadRuntimeListen(rootPath, address string) (string, error) {
	if address == "" {
		return "", nil
	}
	ip, _, err := loopbackPort(address)
	if err != nil {
		return "", err
	}
	root, err := openSettingsRoot(rootPath)
	if os.IsNotExist(err) {
		return address, nil
	}
	if err != nil {
		return "", err
	}
	defer root.Close()
	saved, err := readRuntimePort(root)
	if err != nil {
		return "", err
	}
	if saved.Port == 0 {
		return address, nil
	}
	return net.JoinHostPort(ip, strconv.Itoa(saved.Port)), nil
}
func (h *Host) runtimeSettings() (RuntimeSettings, error) {
	state := RuntimeSettings{Transport: "stdio"}
	if h.runtimeListen != "" {
		_, port, err := loopbackPort(h.runtimeListen)
		if err != nil {
			return state, err
		}
		state.Transport = "http"
		state.CurrentAddress = h.runtimeListen
		state.CurrentPort = port
		state.SavedPort = port
	}
	root, err := openSettingsRoot(h.runtimeSettingsRoot)
	if err != nil {
		return state, errRuntimeSettings
	}
	defer root.Close()
	saved, err := readRuntimePort(root)
	if err != nil {
		return state, err
	}
	state.Revision = saved.Revision
	if saved.Port != 0 {
		state.SavedPort = saved.Port
	}
	state.RestartRequired = state.Transport == "http" && state.SavedPort != state.CurrentPort
	return state, nil
}
func (h *Host) saveRuntimePort(expected, port int) (RuntimeSettings, error) {
	if h.runtimeListen == "" || expected < 0 || port < 1 || port > 65535 {
		return RuntimeSettings{}, errRuntimeSettings
	}
	root, err := openSettingsRoot(h.runtimeSettingsRoot)
	if err != nil {
		return RuntimeSettings{}, errRuntimeSettings
	}
	defer root.Close()
	lock, err := root.OpenFile(".mcp-port.lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return RuntimeSettings{}, errRuntimeSettings
	}
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil || !settingsFileSafe(info) || unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return RuntimeSettings{}, errRuntimeSettings
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	saved, err := readRuntimePort(root)
	if err != nil || saved.Revision != expected || saved.Revision == int(^uint(0)>>1) {
		return RuntimeSettings{}, errRuntimeSettings
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return RuntimeSettings{}, errRuntimeSettings
	}
	name := ".mcp-port-write-" + hex.EncodeToString(nonce[:])
	defer root.Remove(name)
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return RuntimeSettings{}, errRuntimeSettings
	}
	data, _ := json.Marshal(runtimePort{Port: port, Revision: saved.Revision + 1})
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || root.Rename(name, ".mcp-port.json") != nil {
		return RuntimeSettings{}, errRuntimeSettings
	}
	dir, err := root.Open(".")
	if err != nil {
		return RuntimeSettings{}, errRuntimeSettings
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return RuntimeSettings{}, errRuntimeSettings
	}
	return h.runtimeSettings()
}
