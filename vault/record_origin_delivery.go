package vault

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/viant/mechanize/auth"
)

// ErrCredentialConfiguration reports only that a unique eligible credential is
// not configured. Record names, endpoints, values and match counts stay private.
var ErrCredentialConfiguration = errors.New("vault credential configuration required")

// ResolveOriginRecordDelivery is an internal host composition primitive, never
// an MCP lookup. It selects exactly one typed Basic record for the target HTTPS
// origin under actual reusable control consent. authorize must recheck the
// private consent service; a ConsentBinding is caller intent, not authority.
// No record identifier, arbitrary key, or NativeHuman context is accepted.
func ResolveOriginRecordDelivery(ctx context.Context, store *RecordStore, target Target, expires time.Time, authorize func(context.Context) error) (*RecordDelivery, string, error) {
	p, e := auth.FromContext(ctx)
	c, ok := auth.ConsentBindingFromContext(ctx)
	if e != nil || p.Validate() != nil || p.ClientID == "" || !p.HasScope("desktop:control") || auth.NativeHuman(ctx) || !ok || c.SessionID == "" || c.GrantID == "" || c.Purpose == "" || authorize == nil {
		return nil, "", auth.ErrUnauthorized
	}
	if store == nil || target.Validate() != nil || !expires.After(time.Now()) || expires.After(time.Now().Add(5*time.Minute)) || ctx.Err() != nil {
		return nil, "", ErrUnavailable
	}
	if authorize(ctx) != nil {
		return nil, "", auth.ErrUnauthorized
	}
	var selected RecordMetadata
	matches := 0
	e = store.store.writeLock(ctx, func() error {
		ids, e := store.ids()
		if e != nil {
			return ErrUnavailable
		}
		for _, id := range ids {
			if ctx.Err() != nil {
				return ErrUnavailable
			}
			meta, plain, e := store.load(ctx, p.Namespace, id)
			if errors.Is(e, ErrMissing) {
				clear(plain)
				continue
			}
			if e != nil {
				clear(plain)
				return ErrUnavailable
			}
			eligible := originBasicRecord(plain, target.Origin)
			clear(plain)
			if eligible {
				matches++
				selected = meta
			}
		}
		if ctx.Err() != nil || authorize(ctx) != nil {
			return auth.ErrUnauthorized
		}
		if matches != 1 {
			return ErrCredentialConfiguration
		}
		return nil
	})
	if e != nil {
		return nil, "", e
	}
	d := &RecordDelivery{state: &recordDeliveryState{store: store, actor: p, consent: c, target: target, metadata: selected, expires: expires}}
	return d, selected.Revision, nil
}

func originBasicRecord(plain []byte, origin string) bool {
	_, fields, e := parseRecord(plain)
	if e != nil {
		return false
	}
	kind, typed, e := scyRecordType(fields)
	if e != nil || !typed || kind != "basic" {
		return false
	}
	// Match byte-for-byte, allowing only one optional trailing slash. URL
	// normalization must not silently widen authority to paths, query or userinfo.
	endpoint := scyField(fields, "endpoint")
	expected := []byte(origin)
	match := bytes.Equal(endpoint, expected) || len(endpoint) == len(expected)+1 && endpoint[len(endpoint)-1] == '/' && bytes.Equal(endpoint[:len(endpoint)-1], expected)
	if !match {
		return false
	}
	// Validate the byte views directly: origin resolution needs no Scy string
	// objects and must not copy the username/password into immutable allocations.
	user, password := scyField(fields, "username"), scyField(fields, "password")
	return scyOnlyFields(fields, scyTypeField, "username", "password", "endpoint", "email") && scyText(user, true) && scyText(password, true) && len(user)+len(password) <= maxCredentialBytes && scyText(scyField(fields, "email"), false)
}
