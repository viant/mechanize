package model

import (
	"strings"
	"testing"
)

func TestReplaceTextRequiresExplicitNativeProcessAndBoundedText(t *testing.T) {
	for _, mode := range []string{"valid", "empty", "web", "noPID", "noBirth", "all", "oversize", "NUL", "invalidUTF8"} {
		t.Run(mode, func(t *testing.T) {
			s := windowPositionStep()
			s.Action = "element.replaceText"
			s.Arguments = map[string]Value{"value": {Kind: StringValue, String: "nonsecret literal"}}
			switch mode {
			case "empty":
				s.Arguments["value"] = Value{Kind: StringValue}
			case "web":
				s.Target.Surface = Surface{Kind: "web", Origin: "https://example.com"}
			case "noPID":
				s.Target.Surface.ProcessID = 0
				s.Target.Surface.ProcessStartToken = ""
			case "noBirth":
				s.Target.Surface.ProcessStartToken = ""
			case "all":
				s.Target.Cardinality = "all"
			case "oversize":
				s.Arguments["value"] = Value{Kind: StringValue, String: strings.Repeat("a", 65537)}
			case "NUL":
				s.Arguments["value"] = Value{Kind: StringValue, String: "nul\x00text"}
			case "invalidUTF8":
				s.Arguments["value"] = Value{Kind: StringValue, String: string([]byte{255})}
			}
			err := s.Validate()
			if (err == nil) != (mode == "valid" || mode == "empty") {
				t.Fatal(mode, err)
			}
		})
	}
}
func TestReplaceTextReferencesRemainTypedAndResolvedBoundsChecked(t *testing.T) {
	s := windowPositionStep()
	s.Action = "element.replaceText"
	s.Arguments = map[string]Value{"value": {Kind: ReferenceValue, Expected: StringValue, Ref: "input.text"}}
	if e := s.Validate(); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ResolveArguments(map[string]Value{"input.text": {Kind: StringValue, String: strings.Repeat("a", 65536)}}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ResolveArguments(map[string]Value{"input.text": {Kind: StringValue, String: strings.Repeat("a", 65537)}}); e == nil {
		t.Fatal("oversized referenced text admitted")
	}
}
