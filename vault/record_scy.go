package vault

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/viant/scy/cred"
)

const scyTypeField = "$scy.type"
const scyPayloadField = "$scy.payload"

// These encrypted field names adapt Scy's actual credential primitives without
// changing MVLT v2, key custody, or exposing a Scy secret/target to callers.
// Basic stays compatible with already-deployed username/password consumers.
func scyRecordType(fields [][2][]byte) (string, bool, error) {
	var kind []byte
	payload := false
	for _, field := range fields {
		if bytes.Equal(field[0], []byte(scyTypeField)) {
			kind = field[1]
		}
		if bytes.Equal(field[0], []byte(scyPayloadField)) {
			payload = true
		}
	}
	if kind == nil {
		if payload {
			return "", true, ErrRecord
		}
		return "", false, nil
	}
	switch string(kind) {
	case "raw", "basic", "key", "sha1", "aws", "azure", "ssh", "generic", "jwt", "oauth2", "certificate", "x509":
		return string(kind), true, nil
	}
	return "", true, ErrRecord
}
func scyField(fields [][2][]byte, name string) []byte {
	for _, field := range fields {
		if bytes.Equal(field[0], []byte(name)) {
			return field[1]
		}
	}
	return nil
}
func scyOnlyFields(fields [][2][]byte, names ...string) bool {
	for _, field := range fields {
		found := false
		for _, name := range names {
			if bytes.Equal(field[0], []byte(name)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func scyText(value []byte, required bool) bool {
	return (!required || len(value) > 0) && utf8.Valid(value) && !bytes.ContainsRune(value, 0)
}

// Validation is for native writes and private typed consumption. parseRecord
// remains structural so previously stored generic records stay inventory-readable.
func validateScyRecordFields(fields [][2][]byte) error {
	kind, typed, e := scyRecordType(fields)
	if e != nil {
		return ErrRecord
	}
	if !typed {
		return nil
	}
	target, e := cred.TargetType(kind)
	if e != nil {
		return ErrRecord
	} // Never return Scy's value-bearing error.
	switch kind {
	case "raw":
		if target != nil || len(fields) != 2 || !scyOnlyFields(fields, scyTypeField, "secret") || len(scyField(fields, "secret")) == 0 {
			return ErrRecord
		}
		return nil
	case "basic":
		_, e := scyBasicCredentials(fields)
		return e
	case "key":
		if target != reflect.TypeOf(cred.SecretKey{}) || len(fields) != 3 || !scyOnlyFields(fields, scyTypeField, "Key", "Secret") || !scyText(scyField(fields, "Key"), true) || !scyText(scyField(fields, "Secret"), true) {
			return ErrRecord
		}
		// Interpret the exact fields through Scy's primitive; never SetEnv/Cipher or
		// any operation with filesystem/network effects.
		value := cred.SecretKey{Key: string(scyField(fields, "Key")), Secret: string(scyField(fields, "Secret"))}
		valid := value.Key != "" && value.Secret != ""
		value = cred.SecretKey{}
		if !valid {
			return ErrRecord
		}
		return nil
	default:
		if target == nil || len(fields) != 2 || !scyOnlyFields(fields, scyTypeField, scyPayloadField) {
			return ErrRecord
		}
		payload := scyField(fields, scyPayloadField)
		if !utf8.Valid(payload) || len(bytes.TrimSpace(payload)) == 0 || bytes.TrimSpace(payload)[0] != '{' || !scyJSONClosed(payload, 0) {
			return ErrRecord
		}
		value := reflect.New(target)
		defer eraseScyValue(value)
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if decoder.Decode(value.Interface()) != nil || decoder.Decode(new(any)) != io.EOF {
			return ErrRecord
		}
		return nil
	}
}

// Strings in Scy's structs use Go's immutable representation. Keep those
// objects local, release references promptly, and wipe owned mutable buffers;
// do not claim that Go's collector securely erases immutable string allocations.
func eraseScyValue(value reflect.Value) {
	if !value.IsValid() {
		return
	}
	switch value.Kind() {
	case reflect.Pointer:
		if !value.IsNil() {
			eraseScyValue(value.Elem())
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			eraseScyValue(value.Field(i))
		}
	case reflect.Slice:
		for i := 0; i < value.Len(); i++ {
			eraseScyValue(value.Index(i))
		}
	}
	if value.CanSet() {
		value.SetZero()
	}
}

// Duplicate keys (including case aliases accepted by encoding/json) and deep
// nested payloads are rejected before Scy's concrete struct decoder sees them.
// Raw values are byte buffers, wiped after traversal; no value is formatted.
func scyJSONClosed(raw []byte, depth int) bool {
	if depth > 16 || !json.Valid(raw) {
		return false
	}
	trim := bytes.TrimSpace(raw)
	if len(trim) == 0 {
		return false
	}
	if trim[0] != '{' && trim[0] != '[' {
		return true
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	opening, e := d.Token()
	if e != nil {
		return false
	}
	var seen []string
	count := 0
	for d.More() {
		count++
		if count > 1024 {
			return false
		}
		if opening == json.Delim('{') {
			token, e := d.Token()
			key, ok := token.(string)
			if e != nil || !ok {
				return false
			}
			for _, previous := range seen {
				if strings.EqualFold(previous, key) {
					return false
				}
			}
			seen = append(seen, key)
		}
		var child json.RawMessage
		if d.Decode(&child) != nil {
			return false
		}
		ok := scyJSONClosed(child, depth+1)
		clear(child)
		if !ok {
			return false
		}
	}
	// A credential object containing no fields is not a typed secret.
	return depth != 0 || count > 0
}

// Only the basic target is eligible for private browser credential delivery.
// The returned views still point into the caller-owned decrypted record buffer.
func scyBasicCredentials(fields [][2][]byte) (Credentials, error) {
	if !scyOnlyFields(fields, scyTypeField, "username", "password", "endpoint", "email") {
		return Credentials{}, ErrRecord
	}
	user, password := scyField(fields, "username"), scyField(fields, "password")
	if !scyText(user, true) || !scyText(password, true) || len(user)+len(password) > maxCredentialBytes || !scyText(scyField(fields, "endpoint"), false) || !scyText(scyField(fields, "email"), false) {
		return Credentials{}, ErrRecord
	}
	basic := cred.Basic{Username: string(user), Password: string(password), Endpoint: string(scyField(fields, "endpoint")), Email: string(scyField(fields, "email"))}
	valid := basic.Username != "" && basic.Password != "" && basic.EncryptedPassword == ""
	basic = cred.Basic{}
	if !valid {
		return Credentials{}, ErrRecord
	}
	return Credentials{username: user, password: password}, nil
}
