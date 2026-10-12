package chrome

import (
	"crypto/rand"
	"encoding/hex"
)

// Private credential requests and privacy permits use the Chrome private wire
// contract: 32 random bytes encoded as 64 lowercase hexadecimal characters.
// Ordinary channel and renderer lease identifiers retain their own contract.
func newPrivateID() string {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(value[:])
}
