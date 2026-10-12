package vault

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/viant/mechanize/auth"
	"golang.org/x/sys/unix"
)

const importDomain = "mechanize.vault.native-import.v1"
const importPrefix = ".import-"

type importReceipt struct {
	Version     string `json:"version"`
	Namespace   string `json:"namespace"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Revision    string `json:"revision"`
}
type importEnvelope struct {
	Receipt importReceipt `json:"receipt"`
	Tag     []byte        `json:"tag"`
}

func importIdentity(ns string, ref Reference, revision string) string {
	raw, _ := json.Marshal([]string{importDomain, ns, ref.ResourceURL, revision})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func importKey(source string) []byte { return []byte(importDomain + ":" + source) }
func (r *RecordStore) importTag(ctx context.Context, receipt importReceipt) ([]byte, error) {
	signer, ok := r.store.cipher.(interface {
		EnvelopeTag(context.Context, string, string, string, []byte) ([]byte, error)
	})
	if !ok {
		return nil, ErrUnavailable
	}
	raw, _ := json.Marshal(receipt)
	return signer.EnvelopeTag(ctx, r.store.version, receipt.Namespace, importDomain+":"+receipt.Source, raw)
}
func (r *RecordStore) readImport(ctx context.Context, ns, source string) (importReceipt, error) {
	raw, e := r.readFile(importPrefix+source, 4096)
	if e != nil {
		return importReceipt{}, e
	}
	var envelope importEnvelope
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&envelope) != nil || d.Decode(new(any)) != io.EOF {
		return importReceipt{}, ErrUnavailable
	}
	canonical, _ := json.Marshal(envelope)
	receipt := envelope.Receipt
	if !bytes.Equal(raw, canonical) || receipt.Version != r.store.version || receipt.Namespace != ns || receipt.Source != source || !nativeRevision(receipt.Destination) || receipt.Revision != "" && !nativeRevision(receipt.Revision) {
		return importReceipt{}, ErrUnavailable
	}
	tag, e := r.importTag(ctx, receipt)
	if e != nil || !hmac.Equal(tag, envelope.Tag) {
		return importReceipt{}, ErrUnavailable
	}
	return receipt, nil
}
func (r *RecordStore) writeImport(ctx context.Context, receipt importReceipt, create bool) error {
	tag, e := r.importTag(ctx, receipt)
	if e != nil {
		return ErrUnavailable
	}
	raw, e := json.Marshal(importEnvelope{receipt, tag})
	if e != nil || len(raw) > 4096 {
		return ErrUnavailable
	}
	random := make([]byte, 16)
	if _, e = rand.Read(random); e != nil {
		return ErrUnavailable
	}
	name := "." + hex.EncodeToString(random) + ".tmp"
	f, e := r.store.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return ErrUnavailable
	}
	defer r.store.root.Remove(name)
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	target := importPrefix + receipt.Source
	if create {
		if _, e = r.store.root.Lstat(target); !os.IsNotExist(e) {
			return ErrConflict
		}
	}
	if e = r.store.root.Rename(name, target); e != nil {
		return ErrUnavailable
	}
	return r.sync()
}

// ImportCredential is reachable only from the authenticated native console and
// its independently confirmed entry window. No values traverse RPC or Swift.
// A durable authenticated reservation precedes the copy. An existing reservation
// is inspected, never replayed; missing/modified destinations remain unresolved.
func (s *NativeRecordInputService) ImportCredential(ctx context.Context, source *NativeInputService, target Target, ref Reference, revision string, inspect bool) (RecordMetadata, error) {
	p, e := auth.FromContext(ctx)
	if e != nil || p.Validate() != nil || p.ClientID == "" || !auth.NativeHuman(ctx) || !p.HasScope("consent:admin") {
		return RecordMetadata{}, auth.ErrUnauthorized
	}
	if s == nil || source == nil || source.store == nil || s.ExposureGate() == nil || source.ExposureGate() != s.ExposureGate() || !sharedRecordCustody(source.store, s.store) || target.Validate() != nil || !nativeRevision(revision) || ref.ResourceURL != reference(p.Namespace, target) {
		return RecordMetadata{}, ErrUnavailable
	}
	hash := importIdentity(p.Namespace, ref, revision)
	return s.protect(ctx, target, func(call *nativeRecordCall) error {
		var receipt importReceipt
		existing := false
		e := s.store.store.writeLock(ctx, func() error {
			if _, e := s.store.ids(); e != nil {
				return e
			}
			var e error
			receipt, e = s.store.readImport(ctx, p.Namespace, hash)
			if e == nil {
				existing = true
				return nil
			}
			if e != ErrMissing {
				return e
			}
			if inspect {
				return ErrMissing
			}
			// Reserve only after checking the exact legacy revision, below. No secret
			// bytes are written until that reservation is durable.
			return nil
		})
		if e != nil {
			return e
		}
		if existing {
			return source.store.ConsumeRevision(ctx, target, ref, revision, func(credentials Credentials) error {
				return credentials.WithBytes(func(username, password []byte) error {
					return s.store.store.writeLock(ctx, func() error {
						latest, e := s.store.readImport(ctx, p.Namespace, hash)
						if e != nil || latest != receipt {
							return ErrNativeOutcomeUnknown
						}
						meta, plain, e := s.store.load(ctx, p.Namespace, receipt.Destination)
						defer clear(plain)
						if e != nil || receipt.Revision != "" && meta.Revision != receipt.Revision {
							return ErrNativeOutcomeUnknown
						}
						key, fields, e := parseRecord(plain)
						if e != nil || !bytes.Equal(key, importKey(hash)) || len(fields) != 2 {
							return ErrNativeOutcomeUnknown
						}
						c, e := recordCredentials(plain)
						if e != nil || !hmac.Equal(c.username, username) || !hmac.Equal(c.password, password) {
							return ErrNativeOutcomeUnknown
						}
						call.result = meta
						return nil // Read-only reconciliation, including prepared receipts.
					})
				})
			})
		}
		return source.store.ConsumeRevision(ctx, target, ref, revision, func(credentials Credentials) error {
			id := make([]byte, 32)
			if _, e := rand.Read(id); e != nil {
				return ErrUnavailable
			}
			receipt = importReceipt{Version: s.store.store.version, Namespace: p.Namespace, Source: hash, Destination: hex.EncodeToString(id)}
			e := s.store.store.writeLock(ctx, func() error {
				count, e := s.store.importCount()
				if e != nil || count >= maxRecordFiles {
					return ErrUnavailable
				}
				if _, e := s.store.readImport(ctx, p.Namespace, hash); e != ErrMissing {
					return ErrConflict
				}
				call.started = true
				return s.store.writeImport(ctx, receipt, true)
			})
			if e != nil {
				return e
			}
			var meta RecordMetadata
			e = credentials.WithBytes(func(username, password []byte) error {
				values, e := NewRecordValues(importKey(hash), [][2][]byte{{[]byte("username"), append([]byte(nil), username...)}, {[]byte("password"), append([]byte(nil), password...)}})
				if e != nil {
					return e
				}
				meta, e = s.store.create(ctx, values, receipt.Destination)
				return e
			})
			if e != nil {
				return e
			}
			e = s.store.store.writeLock(ctx, func() error {
				previous, e := s.store.readImport(ctx, p.Namespace, hash)
				if e != nil || previous != receipt {
					return ErrNativeOutcomeUnknown
				}
				receipt.Revision = meta.Revision
				return s.store.writeImport(ctx, receipt, false)
			})
			if e != nil {
				return e
			}
			call.result = meta
			return nil
		})
	})
}
func (r *RecordStore) importCount() (int, error) {
	dir, e := r.store.root.Open(".")
	if e != nil {
		return 0, ErrUnavailable
	}
	defer dir.Close()
	entries, e := dir.ReadDir(2*maxRecordFiles + 3)
	if e != nil && e != io.EOF {
		return 0, ErrUnavailable
	}
	if len(entries) > 2*maxRecordFiles+2 {
		return 0, ErrUnavailable
	}
	n := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), importPrefix) {
			n++
		}
	}
	return n, nil
}
