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
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/viant/mechanize/backend/containerbrowser"
	"github.com/viant/mechanize/script"
)

type config struct {
	Listen                  string        `json:"listen"`
	Node                    string        `json:"node"`
	Worker                  string        `json:"worker"`
	AllowedOrigins          []string      `json:"allowedOrigins"`
	AllowAllWeb             bool          `json:"allowAllWeb"`
	AllowMutation           bool          `json:"allowMutation"`
	OperationTimeoutSeconds int           `json:"operationTimeoutSeconds"`
	InspectionOnly          bool          `json:"inspectionOnly"`
	BearerTokenFile         string        `json:"bearerTokenFile"`
	NetworkRules            []networkRule `json:"networkRules,omitempty"`
}
type networkRule struct {
	Origin     string            `json:"origin"`
	Path       string            `json:"path"`
	Parameters map[string]string `json:"parameters"`
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
	var bearerToken []byte
	if c.BearerTokenFile != "" {
		info, err := os.Stat(c.BearerTokenFile)
		if err != nil {
			return errors.New("cannot read service token file")
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
			return errors.New("service token file must be private and bounded")
		}
		bearerToken, err = os.ReadFile(c.BearerTokenFile)
		if err != nil {
			return errors.New("cannot read service token file")
		}
		bearerToken = []byte(strings.TrimSpace(string(bearerToken)))
		if len(bearerToken) < 32 {
			return errors.New("service token requires at least 32 bytes")
		}
	}
	workerPolicy, err := json.Marshal(struct {
		AllowedOrigins []string      `json:"allowedOrigins"`
		AllowAllWeb    bool          `json:"allowAllWeb"`
		InspectionOnly bool          `json:"inspectionOnly"`
		NetworkRules   []networkRule `json:"networkRules,omitempty"`
	}{c.AllowedOrigins, c.AllowAllWeb, c.InspectionOnly, c.NetworkRules})
	if err != nil {
		return err
	}
	workerEnv := append(os.Environ(), "MECHANIZE_BROWSER_POLICY="+string(workerPolicy))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Worker lifetime outlasts request cancellation; shutdown closes contexts first.
	worker, err := containerbrowser.Start(context.Background(), c.Node, c.Worker, workerEnv, os.Stderr)
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
	host.InspectionOnly = c.InspectionOnly
	host.BearerToken = bearerToken
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
	if c.InspectionOnly {
		if c.AllowAllWeb || len(c.AllowedOrigins) == 0 {
			return c, errors.New("inspection mode requires an explicit origin allowlist")
		}
		// Navigation has an effect in the shared compiler; the host narrows actions.
		c.AllowMutation = true
	}
	if len(c.NetworkRules) > 20 {
		return c, errors.New("too many network rules")
	}
	for _, rule := range c.NetworkRules {
		u, err := url.Parse(rule.Origin)
		if err != nil || u.User != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.Scheme+"://"+u.Host != rule.Origin || !strings.HasPrefix(rule.Path, "/") || strings.ContainsAny(rule.Path, "?#") || rule.Parameters == nil || len(rule.Parameters) > 20 {
			return c, errors.New("invalid network rule")
		}
		for key, mode := range rule.Parameters {
			if key == "" || len(key) > 64 || (mode != "value" && mode != "presence") {
				return c, errors.New("invalid network parameter rule")
			}
			for _, char := range key {
				if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("_.-", char)) {
					return c, errors.New("invalid network parameter name")
				}
			}
		}
	}
	return c, nil
}
