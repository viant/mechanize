package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// MaxFrameBytes is deliberately stricter than Chrome's native messaging limits.
const MaxFrameBytes = 256 * 1024

func ReadFrame(reader io.Reader) (json.RawMessage, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := binary.NativeEndian.Uint32(header[:])
	if length == 0 || length > MaxFrameBytes {
		return nil, errors.New("invalid native message length")
	}
	message := make([]byte, length)
	if _, err := io.ReadFull(reader, message); err != nil {
		return nil, err
	}
	if !utf8.Valid(message) || !json.Valid(message) {
		return nil, errors.New("invalid JSON frame")
	}
	return message, nil
}

func WriteFrame(writer io.Writer, message json.RawMessage) error {
	if len(message) == 0 || len(message) > MaxFrameBytes || !utf8.Valid(message) || !json.Valid(message) {
		return errors.New("invalid outgoing JSON frame")
	}
	var header [4]byte
	binary.NativeEndian.PutUint32(header[:], uint32(len(message)))
	for _, part := range [][]byte{header[:], message} {
		for len(part) > 0 {
			n, err := writer.Write(part)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}
