package model

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

func ValidNativeMenuName(name string) bool {
	return name != "" && len(name) <= 256 && utf8.ValidString(name) && strings.TrimSpace(name) != "" && !strings.ContainsFunc(name, unicode.IsControl)
}
