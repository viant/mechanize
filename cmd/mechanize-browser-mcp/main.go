package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/viant/mechanize/backend/containerbrowser"
	"github.com/viant/mechanize/script"
)

type config struct {
	Listen                  string   `json:"listen"`
	Node                    string   `json:"node"`
	Worker                  string   `json:"worker"`
	AllowedOrigins          []string `json:"allowedOrigins"`
	AllowAllWeb             bool     `json:"allowAllWeb"`
	AllowMutation           bool     `json:"allowMutation"`
	OperationTimeoutSeconds int      `json:"operationTimeoutSeconds"`
}

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run() error {
	path := flag.String("config", "", "private browser MCP configuration JSON")
	flag.Parse()
	if *path == "" {
		return errors.New("-config required")
	}
	file, err := os.Open(*path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("configuration must be private (0600)")
	}
	c, err := decodeConfig(file)
	if err != nil {
		return err
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
	}
	if c.Node == "" {
		c.Node = "node"
	}
	if c.Worker == "" {
		return errors.New("worker runtime path required")
	}
	if c.OperationTimeoutSeconds == 0 {
		c.OperationTimeoutSeconds = 60
	}
	if c.OperationTimeoutSeconds < 1 || c.OperationTimeoutSeconds > 3600 {
		return errors.New("operation timeout must be 1..3600 seconds")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Worker lifetime outlasts request cancellation; shutdown closes contexts first.
	worker, err := containerbrowser.Start(context.Background(), c.Node, c.Worker, os.Environ(), os.Stderr)
	if err != nil {
		return err
	}
	defer worker.Close()
	policy := script.Policy{AllowAllWeb: c.AllowAllWeb, AllowMutation: c.AllowMutation, AllowedSurfaces: map[string]bool{}}
	for _, origin := range c.AllowedOrigins {
		policy.AllowedSurfaces[origin] = true
	}
	host, mcp, err := containerbrowser.NewHost(worker, policy, time.Duration(c.OperationTimeoutSeconds)*time.Second)
	if err != nil {
		return err
	}
	defer host.Close()
	mcp.UseStreamableHTTP(true)
	httpServer := mcp.HTTP(ctx, c.Listen)
	httpServer.Handler = host.HTTP(httpServer.Handler)

	httpServer.ReadHeaderTimeout = 10 * time.Second
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = host.Close()
		_ = httpServer.Shutdown(shutdown)
	}()
	log.Printf("browser MCP listening on %s", c.Listen)
	if err = httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("browser MCP serve: %w", err)
	}
	return nil
}

func decodeConfig(reader io.Reader) (config, error) {
	c := config{AllowAllWeb: true}
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return c, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return c, errors.New("trailing configuration")
	}
	return c, nil
}
