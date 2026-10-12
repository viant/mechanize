package main

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

type inertChannel struct{}

func (inertChannel) Read([]byte) (int, error)    { return 0, io.EOF }
func (inertChannel) Write(b []byte) (int, error) { return len(b), nil }
func (inertChannel) Close() error                { return nil }
func TestCommandHasNoArgumentAuthorityAndBoundsService(t *testing.T) {
	calls := 0
	serve := func(ctx context.Context, encoded string, _ io.ReadWriteCloser, _ *os.File) error {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 240*time.Second || encoded != "signed" {
			t.Fatal("unbounded or changed enrollment")
		}
		return nil
	}
	fd := os.NewFile(100000, "unused-fixture")
	for _, args := range [][]string{{"worker", "--native-human"}, {"worker", "--config=/tmp/x"}} {
		if run(args, "signed", inertChannel{}, fd, serve) != 2 {
			t.Fatal("arguments accepted")
		}
	}
	if run([]string{"worker"}, "", inertChannel{}, fd, serve) != 2 || calls != 0 {
		t.Fatal("missing enrollment invoked service")
	}
	if run([]string{"worker"}, "signed", inertChannel{}, fd, serve) != 0 || calls != 1 {
		t.Fatal("valid closed entry refused")
	}
	if run([]string{"worker"}, "signed", inertChannel{}, fd, func(context.Context, string, io.ReadWriteCloser, *os.File) error { return errors.New("private-error") }) != 1 {
		t.Fatal("service error hidden as success")
	}
}

func TestPrivateProtocolRequiresPipes(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if privatePipe(file) || privatePipe(nil) {
		t.Fatal("non-private protocol descriptor accepted")
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	if !privatePipe(read) || !privatePipe(write) {
		t.Fatal("inherited pipes refused")
	}
}
