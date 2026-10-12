// The isolated worker has no CLI parameters or environment-selected enrollment.
package main

import (
	"context"
	"io"
	"os"
	"sync"
	"time"

	"github.com/viant/mechanize/security/keychain"
)

var embeddedEnrollment string

type privatePipes struct {
	input, output *os.File
	once          sync.Once
}

func (p *privatePipes) Read(b []byte) (int, error)  { return p.input.Read(b) }
func (p *privatePipes) Write(b []byte) (int, error) { return p.output.Write(b) }
func (p *privatePipes) Close() error {
	p.once.Do(func() { p.input.Close(); p.output.Close() })
	return nil
}

func run(args []string, enrollment string, channel io.ReadWriteCloser, console *os.File, serve func(context.Context, string, io.ReadWriteCloser, *os.File) error) int {
	if len(args) != 1 || enrollment == "" || channel == nil || console == nil || serve == nil {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	if serve(ctx, enrollment, channel, console) != nil {
		return 1
	}
	return 0
}
func privatePipe(file *os.File) bool {
	if file == nil {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeNamedPipe != 0
}
func main() {
	// No logs or error interpolation: stdout is exclusively the closed protocol.
	// This hard exit supplements the launcher's kill watchdog if native C hangs.
	watchdog := time.AfterFunc(240*time.Second, func() { os.Exit(1) })
	defer watchdog.Stop()
	if !privatePipe(os.Stdin) || !privatePipe(os.Stdout) {
		os.Exit(2)
	}
	channel := &privatePipes{input: os.Stdin, output: os.Stdout}
	console := os.NewFile(3, "private-console-channel")
	os.Exit(run(os.Args, embeddedEnrollment, channel, console, keychain.RunPackagedCustodyMigration))
}
