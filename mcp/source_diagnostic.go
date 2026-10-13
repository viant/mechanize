package mcp

import (
	"errors"

	"github.com/viant/mechanize/script"
)

// Compiler diagnostics describe the DSL contract without echoing source,
// selector values, literals or an underlying exception.
type scriptValidationDiagnostic struct {
	Code                  string   `json:"code"`
	ValidationCode        string   `json:"validationCode"`
	Message               string   `json:"message"`
	Stage                 string   `json:"stage"`
	Line                  int      `json:"line,omitempty"`
	Column                int      `json:"column,omitempty"`
	DispatchState         string   `json:"dispatchState"`
	AllowedReadAttributes []string `json:"allowedReadAttributes,omitempty"`
}

func (d *scriptValidationDiagnostic) Error() string { return d.Message }

func closedScriptDiagnostic(err error) *scriptValidationDiagnostic {
	var compiler *script.Error
	if !errors.As(err, &compiler) || compiler == nil {
		return nil
	}
	d := &scriptValidationDiagnostic{Code: "scriptValidationFailed", ValidationCode: "invalidDSL", Message: "Script validation failed. Use mechanize_describe for the supported DSL methods and arguments.", Stage: "validation", DispatchState: "notDispatched"}
	if compiler.Stage == "parse" || compiler.Stage == "typecheck" {
		d.Stage = compiler.Stage
	}
	if compiler.Position.Line > 0 && compiler.Position.Line <= 1<<20 && compiler.Position.Column > 0 && compiler.Position.Column <= 1<<20 {
		d.Line, d.Column = compiler.Position.Line, compiler.Position.Column
	}
	if compiler.Stage == "typecheck" && compiler.Message == "unsupported read attribute" {
		d.ValidationCode = "unsupportedReadAttribute"
		d.AllowedReadAttributes = []string{"text", "value", "name", "checked"}
		d.Message = "Unsupported read attribute. Use read(\"text\"), read(\"value\"), read(\"name\") or read(\"checked\"). Native surfaces also support staticText, identifier, role, focused and enabled."
	}
	return d
}
