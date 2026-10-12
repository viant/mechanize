package host

import (
	"bytes"
	"encoding/json"
	"io"
)

func decodeClosedCredential(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 8192 || d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return errPrivateCredential
	}
	return nil
}
