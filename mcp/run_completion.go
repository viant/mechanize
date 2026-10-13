package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

// The optional response controls do not enter the immutable plan/request hash.
// Re-observing a request with another wait budget never admits another action.
func (in *RunInput) UnmarshalJSON(raw []byte) error {
	type plain RunInput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value plain
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	*in = RunInput(value)
	return nil
}

func validateRunCompletion(in *RunInput, plan *model.Plan) error {
	if in.WaitMs < 0 || in.WaitMs > 5000 {
		return errors.New("waitMs must be between 0 and 5000")
	}
	if len(in.OutputBindings) == 0 {
		return nil
	}
	if err := automation.ValidateOutputBindings(in.OutputBindings); err != nil {
		return err
	}
	for _, name := range in.OutputBindings {
		found := false
		for _, step := range plan.Steps {
			if step.Bind == name && (step.Action == "element.read" || step.Action == "browser.openOrigin") {
				found = true
				break
			}
		}
		if !found {
			return errors.New("outputBindings must name declared element.read or browser.openOrigin outputs")
		}
	}
	return nil
}

const operationReplyReserve = 500 * time.Millisecond

func runCompletionResult(ctx context.Context, runtime *automation.Runtime, input *RunInput, session, operation string) (*schema.CallToolResult, *jsonrpc.Error) {
	if input.WaitMs > 0 {
		deadline := time.Now().Add(time.Duration(input.WaitMs) * time.Millisecond)
		if outer, ok := ctx.Deadline(); ok && outer.Add(-operationReplyReserve).Before(deadline) {
			deadline = outer.Add(-operationReplyReserve)
		}
		if time.Until(deadline) > 0 {
			wait, cancel := context.WithDeadline(ctx, deadline)
			_, err := runtime.Wait(wait, session, operation)
			cancel()
			// Waiting is observational. Its own deadline neither cancels the original
			// operation nor replaces its receipt with a transport/dispatch failure.
			if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
				return failure(err)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return failure(err)
	}
	current, err := runtime.Status(ctx, session, operation)
	if err != nil {
		return failure(err)
	}
	runID, _ := runtime.RunReference(ctx, session, operation)
	result := Operation{RunID: runID, ID: operation, SessionID: session, ExecutionStatus: current.Status, Error: current.Error}
	if current.Status == "succeeded" && len(input.OutputBindings) > 0 {
		outputs, err := runtime.OperationOutputs(ctx, session, operation, input.OutputBindings)
		if err != nil {
			return failure(err)
		}
		result.Outputs = &outputs
	}
	return operationResult(ctx, runtime, result)
}
