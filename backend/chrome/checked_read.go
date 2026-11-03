package chrome

import "github.com/viant/mechanize/model"

// Absence (including an older renderer), mixed state and text values never
// establish false. Checked observation carries its own explicit boolean.
func checkedReplyValue(reply Reply) (model.Value, error) {
	if reply.Checked == nil || reply.Value != nil || reply.ValueReadVersion != 0 || reply.ValueReadBytes != nil {
		return model.Value{}, browserError("attributeUnavailable", "Explicit boolean checked state unavailable", "notDispatched")
	}
	return model.Value{Kind: model.BoolValue, Bool: *reply.Checked}, nil
}
