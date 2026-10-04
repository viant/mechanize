package mcp

import (
	"context"
	"errors"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	"github.com/viant/mechanize/auth"
	scenarios "github.com/viant/mechanize/engine/scenario"
)

func registerScenarios(base *protocol.DefaultHandler, service *scenarios.Service) error {
	if service == nil {
		return nil
	}
	if err := protocol.RegisterTool[*scenarios.PublishDraftRequest, *scenarios.PublishResult](base.Registry, "mechanize_scenario_publish", "Publish an immutable parameterized scenario draft in your own catalogue. Requires typed plan/objective/input and provenance declarations; review claims do not qualify it. Rejects captured action values/defaults/live refs. Does not execute.", func(ctx context.Context, in *scenarios.PublishDraftRequest) (*schema.CallToolResult, *jsonrpc.Error) {
		if in == nil {
			return failure(errors.New("scenario draft required"))
		}
		p, err := auth.FromContext(ctx)
		if err != nil {
			return failure(err)
		}
		published, err := service.PublishDraft(ctx, p, *in)
		if err != nil {
			var uncertain *scenarios.PublicationError
			if errors.As(err, &uncertain) {
				r, rpcErr := result(map[string]any{"code": "scenarioPublicationUnconfirmed", "message": "Inspect the exact owned catalogue revision before another publication", "publicationConfirmed": false, "dispatchState": "notDispatched"})
				bad := true
				r.IsError = &bad
				return r, rpcErr
			}
			return failure(err)
		}
		return result(published)
	}); err != nil {
		return err
	}
	if err := protocol.RegisterTool[*scenarios.ListRequest, *scenarios.ListResult](base.Registry, "mechanize_scenario_list", "List bounded compact owned scenario summaries with keyset pagination and optional objective/exact revision filters. Catalogue membership and review claims never grant execution or qualification.", func(ctx context.Context, in *scenarios.ListRequest) (*schema.CallToolResult, *jsonrpc.Error) {
		if in == nil {
			in = &scenarios.ListRequest{}
		}
		p, err := auth.FromContext(ctx)
		if err != nil {
			return failure(err)
		}
		listed, err := service.List(ctx, p, *in)
		if err != nil {
			return failure(err)
		}
		return result(listed)
	}); err != nil {
		return err
	}
	return protocol.RegisterTool[*scenarios.SelectRequest, *scenarios.Selection](base.Registry, "mechanize_scenario_select", "Propose an exact owned scenario matching objective, entity, typed inputs and trusted fresh environment/qualification. Caller cannot supply qualification or environment authority. Absent/stale/unqualified evidence returns needsAttention. Selection never executes or grants consent.", func(ctx context.Context, in *scenarios.SelectRequest) (*schema.CallToolResult, *jsonrpc.Error) {
		if in == nil {
			return failure(errors.New("scenario selection request required"))
		}
		p, err := auth.FromContext(ctx)
		if err != nil {
			return failure(err)
		}
		selected, err := service.Select(ctx, p, *in)
		if err != nil {
			return failure(err)
		}
		return result(selected)
	})
}
