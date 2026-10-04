package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/host"
)

func main() {
	log.SetOutput(os.Stderr)
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run() error {
	command := "serve"
	if len(os.Args) > 1 && os.Args[1] == "doctor" {
		command = "doctor"
	}
	args := os.Args[1:]
	if len(args) > 0 && (args[0] == "serve" || args[0] == "doctor") {
		args = args[1:]
	}
	flags := flag.NewFlagSet("mechanize "+command, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "", "private JSON configuration path")
	listen := flags.String("listen", "", "authenticated loopback HTTP address; empty selects stdio")
	helper := flags.String("helper", "", "native helper absolute path for nonprompting doctor")
	if err := flags.Parse(args); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if command == "doctor" {
		if *helper == "" {
			return errors.New("doctor requires -helper")
		}
		client, err := native.NewClient(ctx, native.Options{HelperPath: *helper, Stderr: os.Stderr})
		if err != nil {
			return err
		}
		defer client.Close()
		reply, err := client.Call(ctx, native.Request{RequestID: "doctor", Method: "doctor", DeadlineRemainingMS: 3000})
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(reply)
	}
	if *configPath == "" {
		return errors.New("serve requires -config; no anonymous/default namespace")
	}
	info, err := os.Stat(*configPath)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("configuration must be private (0600)")
	}
	file, err := os.Open(*configPath)
	if err != nil {
		return err
	}
	cfg, err := host.DecodeConfig(file)
	_ = file.Close()
	if err != nil {
		return err
	}
	h, err := host.New(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_ = h.Close(shutdown)
	}()
	if *listen == "" {
		secured, err := h.StdioContext(ctx, cfg.StdioCredential)
		if err != nil {
			return err
		}
		stdio := h.Server.Stdio(secured)
		original := os.Stdout
		os.Stdout = os.Stderr
		defer func() { os.Stdout = original }()
		return stdio.ListenAndServe()
	}
	address, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return err
	}
	ip := net.ParseIP(address)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("this development host requires an explicit loopback IP")
	}
	server := h.Server.HTTP(ctx, *listen)
	server.Handler = h.Verifier.Middleware(server.Handler)
	server.ReadHeaderTimeout = 10 * time.Second
	go func() {
		<-ctx.Done()
		shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_ = server.Shutdown(shutdown)
	}()
	if err = server.ListenAndServe(); errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
