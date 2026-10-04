package model

import "strings"

// ValidateWindowFrameClick accepts only a dedicated capture permit and two
// integer pixels in its returned frame. Screen coordinates/buttons are absent.
func ValidateWindowFrameClick(v Value) error {
	if v.Kind != ObjectValue || len(v.Object) != 3 {
		return argumentError("closed captureRef, x and y frame-pixel object required")
	}
	ref, ok := v.Object["captureRef"]
	if !ok || ref.Kind != StringValue && ref.Kind != ReferenceValue {
		return argumentError("typed capture permit reference required")
	}
	if ref.Kind == ReferenceValue {
		if ref.Expected != StringValue {
			return argumentError("captureRef requires typed string reference")
		}
	} else if ref.String == "" || len(ref.String) > 256 || strings.TrimSpace(ref.String) != ref.String || strings.ContainsAny(ref.String, "\x00\r\n") {
		return argumentError("bounded capture permit reference required")
	}
	for _, key := range []string{"x", "y"} {
		point, ok := v.Object[key]
		if !ok {
			return argumentError("x and y frame pixels required")
		}
		if point.Kind == ReferenceValue {
			if point.Expected != NumberValue {
				return argumentError("frame pixels require typed integers")
			}
		} else if point.Kind != NumberValue || point.Number < 0 || point.Number > 32767 {
			return argumentError("frame pixels require bounded nonnegative integers")
		}
	}
	return nil
}

func WindowFrameClick(v Value) (string, int64, int64, error) {
	if err := ValidateWindowFrameClick(v); err != nil {
		return "", 0, 0, err
	}
	ref, x, y := v.Object["captureRef"], v.Object["x"], v.Object["y"]
	if ref.Kind != StringValue || x.Kind != NumberValue || y.Kind != NumberValue {
		return "", 0, 0, argumentError("resolved capture permit and integer frame pixels required")
	}
	return ref.String, x.Number, y.Number, nil
}
