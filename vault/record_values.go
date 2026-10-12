package vault

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

const (
	maxRecordKey       = 1024
	maxRecordFields    = 32
	maxRecordFieldName = 256
	maxRecordPlaintext = 64 * 1024
)

var ErrRecord = errors.New("vault record invalid or already consumed")

// RecordValues owns a bounded arbitrary key and a map of named byte fields.
// It has no plaintext getters or serialization. Copies share one-shot ownership.
// Only a trusted native form may supply these values; never bind this type to MCP.
type RecordValues struct{ state *recordValueState }
type recordValueState struct {
	mu     sync.Mutex
	used   bool
	key    []byte
	fields [][2][]byte
}

// NewRecordValues takes ownership of key and each name/value buffer, including
// on error. Pairs implement a map: duplicate names are rejected. Byte names
// allow erasure; callers must relinquish all aliases and not retain/log buffers.
// Limits are a 1024-byte key, 32 nonempty fields, 256-byte field names, and
// 64 KiB for the complete framed payload. Keys and values may contain any bytes.
func NewRecordValues(key []byte, fields [][2][]byte) (RecordValues, error) {
	if !validRecord(key, fields) || validateScyRecordFields(fields) != nil {
		clear(key)
		for _, field := range fields {
			clear(field[0])
			clear(field[1])
		}
		return RecordValues{}, ErrRecord
	}
	return RecordValues{state: &recordValueState{key: key, fields: append([][2][]byte(nil), fields...)}}, nil
}
func validRecord(key []byte, fields [][2][]byte) bool {
	if len(key) == 0 || len(key) > maxRecordKey || len(fields) == 0 || len(fields) > maxRecordFields {
		return false
	}
	size := 8 + len(key)
	for i, f := range fields {
		if len(f[0]) == 0 || len(f[0]) > maxRecordFieldName || len(f[1]) == 0 || len(f[1]) > maxRecordPlaintext {
			return false
		}
		size += 8 + len(f[0]) + len(f[1])
		if size > maxRecordPlaintext {
			return false
		}
		for j := 0; j < i; j++ {
			if bytes.Equal(f[0], fields[j][0]) {
				return false
			}
		}
	}
	return true
}
func (RecordValues) String() string               { return "[vault record withheld]" }
func (RecordValues) GoString() string             { return "[vault record withheld]" }
func (RecordValues) Format(s fmt.State, _ rune)   { _, _ = s.Write([]byte("[vault record withheld]")) }
func (RecordValues) MarshalJSON() ([]byte, error) { return nil, ErrRecord }
func (RecordValues) MarshalText() ([]byte, error) { return nil, ErrRecord }
func (v RecordValues) Destroy() {
	if v.state == nil {
		return
	}
	v.state.mu.Lock()
	defer v.state.mu.Unlock()
	v.state.wipe()
}
func (v *recordValueState) wipe() {
	clear(v.key)
	for _, f := range v.fields {
		clear(f[0])
		clear(f[1])
	}
	v.key = nil
	v.fields = nil
	v.used = true
}
func (v RecordValues) take() ([]byte, error) {
	if v.state == nil {
		return nil, ErrRecord
	}
	v.state.mu.Lock()
	defer v.state.mu.Unlock()
	defer v.state.wipe()
	if v.state.used || !validRecord(v.state.key, v.state.fields) || validateScyRecordFields(v.state.fields) != nil {
		return nil, ErrRecord
	}
	// Fixed maximum capacity prevents reallocations leaving old plaintext copies.
	b := make([]byte, 0, maxRecordPlaintext)
	appendBytes := func(p []byte) { b = binary.BigEndian.AppendUint32(b, uint32(len(p))); b = append(b, p...) }
	appendBytes(v.state.key)
	b = binary.BigEndian.AppendUint32(b, uint32(len(v.state.fields)))
	for _, f := range v.state.fields {
		appendBytes(f[0])
		appendBytes(f[1])
	}
	return b, nil
}

// Views point into plain, which the caller must wipe after use. The binary
// payload avoids immutable Go string copies of sensitive keys or field names.
func parseRecord(plain []byte) ([]byte, [][2][]byte, error) {
	if len(plain) > maxRecordPlaintext {
		return nil, nil, ErrRecord
	}
	rest := plain
	read := func() ([]byte, bool) {
		if len(rest) < 4 {
			return nil, false
		}
		n := binary.BigEndian.Uint32(rest)
		rest = rest[4:]
		if uint64(n) > uint64(len(rest)) {
			return nil, false
		}
		p := rest[:int(n)]
		rest = rest[int(n):]
		return p, true
	}
	key, ok := read()
	if !ok || len(rest) < 4 {
		return nil, nil, ErrRecord
	}
	count := binary.BigEndian.Uint32(rest)
	rest = rest[4:]
	if count == 0 || count > maxRecordFields {
		return nil, nil, ErrRecord
	}
	fields := make([][2][]byte, 0, int(count))
	for i := uint32(0); i < count; i++ {
		name, ok := read()
		if !ok {
			return nil, nil, ErrRecord
		}
		value, ok := read()
		if !ok {
			return nil, nil, ErrRecord
		}
		fields = append(fields, [2][]byte{name, value})
	}
	if len(rest) != 0 || !validRecord(key, fields) {
		return nil, nil, ErrRecord
	}
	return key, fields, nil
}
