package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"
)

const address = "127.0.0.1:18771"

//go:embed index.html fixture.js
var assets embed.FS

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx); err != nil {
		log.Fatal(err)
	}
}

func serve(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if !allowReadMethod(w, r) {
			return
		}
		secureHeaders(w)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !allowReadMethod(w, r) {
			return
		}
		var name, contentType string
		switch r.URL.Path {
		case "/", "/index.html":
			name, contentType = "index.html", "text/html; charset=utf-8"
		case "/fixture.js":
			name, contentType = "fixture.js", "text/javascript; charset=utf-8"
		default:
			http.NotFound(w, r)
			return
		}
		body, err := fs.ReadFile(assets, name)
		if err != nil {
			http.Error(w, "fixture asset unavailable", http.StatusInternalServerError)
			return
		}
		secureHeaders(w)
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", address, err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		return fmt.Errorf("shutdown fixture: %w", err)
	}
	if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func allowReadMethod(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func secureHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
}
