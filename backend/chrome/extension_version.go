package chrome

import (
	"strconv"
	"strings"
)

// Chrome manifest versions contain one to four decimal components. Keep only
// this bounded diagnostic value; never echo arbitrary handshake text.
func reportedExtensionVersion(value string) string {
	if len(value) == 0 || len(value) > 23 {
		return ""
	}
	parts := strings.Split(value, ".")
	if len(parts) > 4 {
		return ""
	}
	nonzero := false
	for _, part := range parts {
		if len(part) == 0 || len(part) > 5 || len(part) > 1 && part[0] == '0' {
			return ""
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return ""
			}
		}
		n, err := strconv.ParseUint(part, 10, 16)
		if err != nil {
			return ""
		}
		nonzero = nonzero || n != 0
	}
	if !nonzero {
		return ""
	}
	return value
}
