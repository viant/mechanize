package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/google/gops/agent"
)

// startDiagnostics is opt-in local development instrumentation. It is never
// exposed through MCP or inherited from an automation plan.
func startDiagnostics(directory string) (func(), error) {
	if directory == "" {
		return func() {}, nil
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("absolute diagnostics directory required")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return nil, errors.New("physical diagnostics directory required")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || st.Uid != uint32(os.Getuid()) || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private owned diagnostics directory required")
	}
	if err := agent.Listen(agent.Options{Addr: "127.0.0.1:0", ConfigDir: directory}); err != nil {
		agent.Close()
		return nil, err
	}
	return agent.Close, nil
}
