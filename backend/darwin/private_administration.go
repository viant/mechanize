package darwin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"time"
)

var ErrPrivateProof = errors.New("private native proof unavailable")

// PrivateProofError carries only a closed local diagnostic. No native message,
// process/window text, pathname, or provider error reaches the public guard.
type PrivateProofError struct{ code string }

func (e *PrivateProofError) Error() string  { return "private native proof unavailable: " + e.code }
func (e *PrivateProofError) Unwrap() error  { return ErrPrivateProof }
func (e *PrivateProofError) Code() string   { return e.code }
func privateProofFailure(code string) error { return &PrivateProofError{code: code} }
func privateNativeFailure(err error) error {
	var native *NativeError
	if errors.As(err, &native) {
		switch native.Code {
		case "privateAXTrustDenied", "privateConsoleSignatureInvalid", "privateConsoleProcessInvalid", "privateConsoleInventoryUnavailable", "privateAXIPCUnavailable", "privateWindowShapeUnavailable":
			return privateProofFailure(native.Code)
		case "deadlineExceeded":
			return privateProofFailure("privateHelperTimeout")
		case "privateProfileRequired":
			return privateProofFailure("privateHelperProfileUnavailable")
		}
	}
	return privateProofFailure("privateHelperExchangeUnavailable")
}

// PrivateAdministration uses a dedicated authenticated helper profile. It is not
// a Gateway, MCP method, or an ordinary observation/input caller.
type PrivateAdministration struct{ options Options }

func NewPrivateAdministration(options Options) (*PrivateAdministration, error) {
	if options.HelperPath == "" || options.Requirement == "" || options.ExpectedUID == nil || options.AllowMutations || options.AllowLaunch || options.AllowSemantic || options.AllowRecording || options.Artifact != nil || options.Fence != nil {
		return nil, ErrPrivateProof
	}
	options.PrivateAdministration = true
	return &PrivateAdministration{options}, nil
}
func (p *PrivateAdministration) call(ctx context.Context, method string, params map[string]any, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	client, e := NewClient(ctx, p.options)
	if e != nil {
		if client != nil {
			_ = client.Close()
		}
		return privateProofFailure("privateHelperLaunchUnavailable")
	}
	defer client.Close()
	e = p.exchange(ctx, client.Call, method, params, out)
	if client.Close() != nil {
		return privateProofFailure("privateHelperCleanupUnconfirmed")
	}
	return e
}
func (p *PrivateAdministration) exchange(ctx context.Context, call func(context.Context, Request) (Reply, error), method string, params map[string]any, out any) error {
	var random [32]byte
	if _, e := rand.Read(random[:]); e != nil {
		return ErrPrivateProof
	}
	nonce := hex.EncodeToString(random[:])
	params["nonce"] = nonce
	doctor, e := call(ctx, Request{RequestID: nonce + "d", Method: "doctor", DeadlineRemainingMS: 8000})
	if e != nil {
		return privateProofFailure("privateHelperDoctorUnavailable")
	}
	var feature struct {
		Version int `json:"privateAdministrationVersion"`
	}
	if json.Unmarshal(doctor.Result, &feature) != nil || feature.Version != 1 || doctor.HelperEpoch == "" {
		return privateProofFailure("privateHelperProfileUnavailable")
	}
	raw, e := json.Marshal(params)
	if e != nil {
		return ErrPrivateProof
	}
	reply, e := call(ctx, Request{RequestID: nonce, Method: method, HelperEpoch: doctor.HelperEpoch, DeadlineRemainingMS: 8000, Params: raw})
	if e != nil {
		return privateNativeFailure(e)
	}
	if reply.HelperEpoch != doctor.HelperEpoch || closedPrivateReply(reply.Result, out) != nil {
		return privateProofFailure("privateHelperResponseInvalid")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(reply.Result, &fields) != nil {
		return ErrPrivateProof
	}
	expected := []string{"version", "nonce", "consoles", "entries", "matched"}
	if method == "private.managementProof" {
		expected = []string{"version", "nonce", "pid", "birth", "extensionID", "path", "observedAtUnixMilliseconds"}
	}
	if len(fields) != len(expected) {
		return ErrPrivateProof
	}
	for _, key := range expected {
		if _, ok := fields[key]; !ok {
			return ErrPrivateProof
		}
	}
	var binding struct {
		Version int    `json:"version"`
		Nonce   string `json:"nonce"`
	}
	if json.Unmarshal(reply.Result, &binding) != nil || binding.Version != 1 || binding.Nonce != nonce || ctx.Err() != nil {
		return ErrPrivateProof
	}
	return nil
}
func closedPrivateReply(raw []byte, out any) error {
	if len(raw) > 8192 {
		return ErrPrivateProof
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return ErrPrivateProof
	}
	seen := map[string]bool{}
	for d.More() {
		t, e = d.Token()
		k, ok := t.(string)
		if e != nil || !ok || seen[k] {
			return ErrPrivateProof
		}
		seen[k] = true
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return ErrPrivateProof
		}
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrPrivateProof
	}
	return nil
}

type PrivateConsoleWindows struct {
	Version  int    `json:"version"`
	Nonce    string `json:"nonce"`
	Consoles int    `json:"consoles"`
	Entries  int    `json:"entries"`
	Matched  int    `json:"matched"`
}

func (p *PrivateAdministration) ConsoleWindows(ctx context.Context, requirement, entryID string) (PrivateConsoleWindows, error) {
	var result PrivateConsoleWindows
	if p == nil || requirement == "" || len(requirement) > 4096 || entryID != "" && !privateHex(entryID) {
		return result, ErrPrivateProof
	}
	e := p.call(ctx, "private.consoleWindows", map[string]any{"consoleRequirement": requirement, "entryID": entryID}, &result)
	if e != nil {
		return PrivateConsoleWindows{}, e
	}
	if result.Consoles < 0 || result.Consoles > 4 || result.Entries < 0 || result.Entries > 128 || result.Matched < 0 || result.Matched > result.Entries || entryID == "" && result.Matched != 0 {
		return PrivateConsoleWindows{}, ErrPrivateProof
	}
	return result, nil
}
func privateHex(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, c := range v {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

type PrivateManagementRequest struct {
	PID         int    `json:"pid"`
	Birth       string `json:"birth"`
	Title       string `json:"title"`
	ExtensionID string `json:"extensionID"`
	Receipt     []byte `json:"receipt"`
}
type PrivateManagementProof struct {
	Version                    int    `json:"version"`
	Nonce                      string `json:"nonce"`
	PID                        int    `json:"pid"`
	Birth                      string `json:"birth"`
	ExtensionID                string `json:"extensionID"`
	Path                       string `json:"path"`
	ObservedAtUnixMilliseconds int64  `json:"observedAtUnixMilliseconds"`
}

func (p *PrivateAdministration) ManagementProof(ctx context.Context, requirement string, in PrivateManagementRequest) (PrivateManagementProof, error) {
	var out PrivateManagementProof
	if p == nil || requirement == "" || len(requirement) > 4096 || in.PID <= 0 || in.Birth == "" || len(in.Birth) > 128 || in.Title == "" || len(in.Title) > 1024 || len(in.ExtensionID) != 32 || len(in.Receipt) == 0 || len(in.Receipt) > 128*1024 {
		return out, ErrPrivateProof
	}
	for _, c := range in.ExtensionID {
		if c < 'a' || c > 'p' {
			return out, ErrPrivateProof
		}
	}
	e := p.call(ctx, "private.managementProof", map[string]any{"pid": in.PID, "birth": in.Birth, "title": in.Title, "extensionID": in.ExtensionID, "receipt": in.Receipt, "chromeRequirement": requirement}, &out)
	age := time.Since(time.UnixMilli(out.ObservedAtUnixMilliseconds))
	if e != nil || out.PID != in.PID || out.Birth != in.Birth || out.ExtensionID != in.ExtensionID || !filepath.IsAbs(out.Path) || filepath.Clean(out.Path) != out.Path || len(out.Path) > 4096 || age < -time.Second || age > 30*time.Second {
		return PrivateManagementProof{}, ErrPrivateProof
	}
	return out, nil
}
