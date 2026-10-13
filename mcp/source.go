package mcp

import (
	"errors"
	"strings"

	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func compileSource(source, format string) (*model.Plan, error) {
	if len(source) > 1<<20 {
		return nil, errors.New("source exceeds 1 MiB")
	}
	switch format {
	case "", "dsl":
		plan, err := script.Compile(source)
		if diagnostic := closedScriptDiagnostic(err); diagnostic != nil {
			return nil, diagnostic
		}
		return plan, err
	case "json":
		return script.DecodeJSON(strings.NewReader(source))
	case "yaml":
		return script.DecodeYAML(strings.NewReader(source))
	default:
		return nil, errors.New("format must be dsl, json or yaml")
	}
}
