package recordevents

import (
	"context"
	"fmt"
	"github.com/viant/mechanize/data"
)

// Init validates explicit bound identity against the trusted host scope.
func (input *AppendRecordingEventsInput) Init(ctx context.Context) error {
	if len(input.AppendRecordingEvents) > 256 {
		return fmt.Errorf("recording batch exceeds 256 events")
	}
	_, err := data.RequireScope(ctx, input.Namespace)
	return err
}
