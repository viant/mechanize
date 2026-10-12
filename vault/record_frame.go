package vault

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const (
	maxRecordFrameBytes    = 64 * 1024
	recordFrameHeaderBytes = 12
)

var recordFrameMagic = [8]byte{'M', 'V', 'L', 'T', 0, 0, 0, 2}
var ErrRecordFrame = errors.New("native vault record frame rejected")

// Native record frame v2, distinct from the legacy MVLT v1 credential pair:
//
//	8 bytes: "MVLT" followed by 00 00 00 02
//	u32: payload byte length, excluding this 12-byte header
//	payload:
//	  u32 key byte length; key bytes
//	  u32 field count
//	  repeated field count times:
//	    u32 name byte length; name bytes
//	    u32 value byte length; value bytes
//	EOF (exactly one frame per closed input stream)
//
// Every u32 is unsigned big-endian. The complete frame is at most 65536 bytes,
// including the header and all lengths. RecordValues additionally limits keys
// to 1024 bytes, field count to 32, and names to 256 bytes. Keys, names and
// values are nonempty arbitrary bytes; duplicate names are rejected bytewise.
// Field order is preserved, with no normalization, text encoding, or sorting.
//
// These package-private codecs perform no authorization or exposure admission.
// A future signed-native service MUST verify NativeHuman, readiness, exact
// operation/revision and qualified entry protection BEFORE calling the decoder
// (and thus before the first Read). Keep protection held through use/destruction
// of RecordValues. The trusted transport must enforce read/write deadlines and
// close its write half after one frame. Never expose this codec through MCP,
// JSON, browser storage, a generic secret getter, or an unprotected callback.
// No native record service or transport is registered by this file.
func readRecordFrame(reader io.Reader) (RecordValues, error) {
	if reader == nil {
		return RecordValues{}, ErrRecordFrame
	}
	var header [recordFrameHeaderBytes]byte
	defer clear(header[:])
	if _, err := io.ReadFull(reader, header[:]); err != nil || !bytes.Equal(header[:8], recordFrameMagic[:]) {
		return RecordValues{}, ErrRecordFrame
	}
	length := binary.BigEndian.Uint32(header[8:])
	// Bound before conversion/allocation: even a uint32 overflow attempt cannot
	// cause an unbounded read or platform-dependent int conversion.
	if length == 0 || length > maxRecordFrameBytes-recordFrameHeaderBytes {
		return RecordValues{}, ErrRecordFrame
	}
	plain := make([]byte, int(length))
	defer clear(plain)
	if _, err := io.ReadFull(reader, plain); err != nil {
		return RecordValues{}, ErrRecordFrame
	}
	key, fields, err := parseRecord(plain)
	if err != nil {
		return RecordValues{}, ErrRecordFrame
	}
	var extra [1]byte
	defer clear(extra[:])
	if n, err := io.ReadFull(reader, extra[:]); n != 0 || err != io.EOF {
		return RecordValues{}, ErrRecordFrame
	}
	// Transfer exact owned secret buffers, never slices into the frame (whose
	// framing bytes and entire backing allocation are wiped before returning).
	ownedKey := bytes.Clone(key)
	ownedFields := make([][2][]byte, len(fields))
	for i, field := range fields {
		ownedFields[i] = [2][]byte{bytes.Clone(field[0]), bytes.Clone(field[1])}
	}
	result, err := NewRecordValues(ownedKey, ownedFields)
	if err != nil { // Constructor wipes all owned buffers on failure.
		return RecordValues{}, ErrRecordFrame
	}
	return result, nil
}

// writeRecordFrame is only for a trusted native caller after the same entry and
// transport admission. It consumes values once on every path, including a nil
// writer, oversize frame or I/O failure. It returns no plaintext representation;
// writer must obey io.Writer's prohibition on retaining the supplied buffer.
// I/O errors are deliberately replaced so transport errors cannot echo secrets.
func writeRecordFrame(writer io.Writer, values RecordValues) error {
	defer values.Destroy()
	if writer == nil {
		return ErrRecordFrame
	}
	plain, err := values.take()
	if err != nil {
		return ErrRecordFrame
	}
	defer clear(plain)
	if len(plain) > maxRecordFrameBytes-recordFrameHeaderBytes {
		return ErrRecordFrame
	}
	var header [recordFrameHeaderBytes]byte
	defer clear(header[:])
	copy(header[:8], recordFrameMagic[:])
	binary.BigEndian.PutUint32(header[8:], uint32(len(plain)))
	if n, err := writer.Write(header[:]); err != nil || n != len(header) {
		return ErrRecordFrame
	}
	if n, err := writer.Write(plain); err != nil || n != len(plain) {
		return ErrRecordFrame
	}
	return nil
}
