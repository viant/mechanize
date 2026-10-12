// Command devcredential renews only the fixed local development-agent credential.
// It never adopts claims from the old token or prints signing material/tokens.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/viant/mechanize/internal/devcredential"
	"os"
)

type config = devcredential.Config
type report = devcredential.Report

func private(path string) ([]byte, error) { return devcredential.PrivateRead(path) }
func renew(ctx context.Context, path string, apply bool) (report, error) {
	return devcredential.Renew(ctx, path, apply)
}

func main() {
	path := flag.String("config", "", "private development config.json")
	apply := flag.Bool("apply", false, "replace only the development-agent token after Scy signing and verification")
	flag.Parse()
	r, err := renew(context.Background(), *path, *apply)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Development credential renewal rejected; secret details withheld")
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(r)
}
