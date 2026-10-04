package durable

import (
	"context"
	"errors"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data/listrecordingevents"
	"github.com/viant/mechanize/data/recordevents"
)

func (b *Builder) AppendRecordingEvents(ctx context.Context, p auth.Principal, rows []*recordevents.RecordedEvent) error {
	if len(rows) == 0 || len(rows) > 128 {
		return errors.New("recording batch must contain 1...128 journal rows")
	}
	ctx, user, err := b.bound(ctx, p, 0)
	if err != nil {
		return err
	}
	user.mu.Lock()
	defer user.mu.Unlock()
	for _, row := range rows {
		if row == nil || row.Namespace == nil || *row.Namespace != p.Namespace {
			return auth.ErrUnauthorized
		}
	}
	input := &recordevents.AppendRecordingEventsInput{}
	input.SetNamespace(p.Namespace)
	input.SetAppendRecordingEvents(rows)
	_, err = invoke(ctx, user.server, "recordevents", "AppendRecordingEvents", "POST", input, true)
	return err
}
func (b *Builder) ReadRecordingEvents(ctx context.Context, p auth.Principal, id string) ([]*recordevents.RecordedEvent, error) {
	if id == "" || len(id) > 128 {
		return nil, errors.New("bounded recording id required")
	}
	ctx, user, err := b.bound(ctx, p, 0)
	if err != nil {
		return nil, err
	}
	user.mu.Lock()
	defer user.mu.Unlock()
	input := &listrecordingevents.ListRecordingEventsInput{}
	input.SetNamespace(p.Namespace)
	input.SetRecordingID(id)
	value, err := invoke(ctx, user.server, "listrecordingevents", "ListRecordingEvents", "GET", input, false)
	if err != nil {
		return nil, err
	}
	output, ok := value.(*listrecordingevents.ListRecordingEventsOutput)
	if !ok {
		return nil, errors.New("unexpected recording projection")
	}
	if len(output.Data) > 10000 {
		return nil, errors.New("recording journal limit exceeded; export cannot silently truncate")
	}
	result := make([]*recordevents.RecordedEvent, 0, len(output.Data))
	for _, r := range output.Data {
		result = append(result, &recordevents.RecordedEvent{Namespace: r.Namespace, Id: r.Id, RecordingId: r.RecordingId, Sequence: r.Sequence, Kind: r.Kind, PayloadJson: r.PayloadJson, CreatedAt: r.CreatedAt})
	}
	return result, nil
}
