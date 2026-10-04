package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
)

type BrowserStatus func(context.Context, auth.Principal) (chrome.BrowserStatus, error)

func registerBrowserStatus(base *protocol.DefaultHandler, callback BrowserStatus) error {
	if callback == nil {
		return nil
	}
	var input schema.ToolInputSchema
	if err := input.Load((*Empty)(nil)); err != nil {
		return err
	}
	extra, ok := input.AdditionalProperties.(map[string]any)
	if !ok {
		extra = map[string]any{}
	}
	extra["additionalProperties"] = false
	input.AdditionalProperties = extra
	var output schema.ToolOutputSchema
	if err := output.Load((*chrome.BrowserStatus)(nil)); err != nil {
		return err
	}
	base.Registry.RegisterToolWithSchema("mechanize_browser_status", "Read owned browser channel qualification flags, inventory and pending/unknown counts, and static attention codes. No browser input, document content, credentials or authority overrides.", input, &output, func(ctx context.Context, request *schema.CallToolRequest) (*schema.CallToolResult, *jsonrpc.Error) {
		if request == nil {
			return failure(errors.New("empty browser status input required"))
		}
		arguments := request.Params.Arguments
		if arguments == nil {
			arguments = map[string]any{}
		}
		raw, err := json.Marshal(arguments)
		if err != nil || len(raw) > 1024 {
			return failure(errors.New("bounded empty browser status input required"))
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		var in *Empty
		if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF || in == nil {
			return failure(errors.New("closed empty browser status input required"))
		}
		p, err := auth.FromContext(ctx)
		if err != nil {
			return failure(err)
		}
		status, err := callback(ctx, p)
		if err != nil {
			return failure(errors.New("owned browser status unavailable"))
		}
		return result(status)
	})
	return nil
}
