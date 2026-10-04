package chrome

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/scy"
	_ "github.com/viant/scy/kms/blowfish" // Register operator-selected encrypted env-key enrollment.
)

type Enrollment struct {
	TrustScope         string         `json:"trustScope,omitempty"`
	Principal          auth.Principal `json:"principal"`
	ProfileChannel     string         `json:"profileChannel"`
	BrowserInstance    string         `json:"browserInstance"`
	ExtensionOrigin    string         `json:"extensionOrigin"`
	Origins            []string       `json:"origins"`
	CredentialResource scy.Resource   `json:"credentialResource"`
	ProfileDirectory   string         `json:"profileDirectory,omitempty"`
}
type Config struct {
	SocketPath        string                          `json:"socketPath"`
	FixtureEnrollment bool                            `json:"fixtureEnrollment"`
	Grants            []Enrollment                    `json:"grants"`
	ProcessTrust      *nativepeer.ChromeProcessPolicy `json:"processTrust,omitempty"`
}
type pending struct {
	lifecycle     *LifecycleReceiptGuard
	lifecycleDone chan lifecycleReply
	command       Command
	mutation      bool
	done          chan Reply
}
type channel struct {
	lifecycleInhibited         bool
	lifecycleOwner             string
	lifecycleGuard             *LifecycleReceiptGuard
	mutationFingerprintVersion int
	fixtureOnly                bool
	processEvidence            *nativepeer.ChromeProcessEvidence
	profileQualified           bool
	scopeQualified             bool
	attentionCode              string
	executorQualified          bool
	executorChallenge          string
	grant                      Enrollment
	credential                 string
	epoch, scopeHash           string
	conn                       net.Conn
	documents                  []Document
	inventoryComplete          bool
	inventoryAt                time.Time
	pending                    map[string]*pending
	attempts                   map[string]Command
	receipts                   map[string]Reply
	unknown                    map[string]bool
	writeMu                    sync.Mutex
}
type Broker struct {
	processTrust *nativepeer.ChromeProcessPolicy
	verifyPeer   chromePeerCheck
	mu           sync.Mutex
	listener     *net.UnixListener
	channels     map[string]*channel
	connections  map[net.Conn]bool
	epoch        string
	sequence     uint64
	closed       bool
	wg           sync.WaitGroup
	lane         chan struct{}
	recordings   map[string]*recording
}

func channelKey(profile, instance string) string { return profile + "\x00" + instance }
func NewBroker(ctx context.Context, config Config) (*Broker, error) {
	check, err := processPeerCheck(config)
	if err != nil {
		return nil, err
	}
	credentials := map[string]string{}
	for _, grant := range config.Grants {
		r := grant.CredentialResource
		if r.URL == "" || r.Key == "" || r.Fallback != nil || len(r.Data) != 0 {
			return nil, errors.New("encrypted Scy enrollment resource required")
		}
		secret, err := scy.New().Load(ctx, &r)
		if err != nil {
			return nil, errors.New("Scy backend enrollment unavailable")
		}
		credentials[channelKey(grant.ProfileChannel, grant.BrowserInstance)] = strings.TrimSpace(secret.String())
	}
	return newBrokerWithPeer(config, credentials, check)
}
func newBroker(config Config, credentials map[string]string) (*Broker, error) {
	check, err := processPeerCheck(config)
	if err != nil {
		return nil, err
	}
	return newBrokerWithPeer(config, credentials, check)
}
func newBrokerWithPeer(config Config, credentials map[string]string, check chromePeerCheck) (*Broker, error) {
	if !config.FixtureEnrollment && check == nil {
		return nil, errors.New("production signed peer verifier required")
	}

	if !filepath.IsAbs(config.SocketPath) || len(config.Grants) == 0 {
		return nil, errors.New("absolute socket and enrolled grants required")
	}
	parent, err := os.Stat(filepath.Dir(config.SocketPath))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return nil, errors.New("Chrome socket parent must be private")
	}
	if !config.FixtureEnrollment {
		parentPath := filepath.Dir(config.SocketPath)
		canonical, err := filepath.EvalSymlinks(parentPath)
		expectedUID := uint32(os.Getuid())
		if config.ProcessTrust != nil {
			expectedUID = config.ProcessTrust.ExpectedUID
		}
		owner, ok := parent.Sys().(*syscall.Stat_t)
		if err != nil || canonical != parentPath || !ok || owner.Uid != expectedUID {
			return nil, errors.New("production Chrome socket parent must be canonical and owned by enrolled UID")
		}
	}
	b := &Broker{verifyPeer: check, channels: map[string]*channel{}, connections: map[net.Conn]bool{}, epoch: newID(), lane: make(chan struct{}, 1), recordings: map[string]*recording{}}
	if config.ProcessTrust != nil {
		copy := *config.ProcessTrust
		b.processTrust = &copy
	}
	for _, grant := range config.Grants {
		key := channelKey(grant.ProfileChannel, grant.BrowserInstance)
		grant.TrustScope, err = NormalizeTrustScope(grant.TrustScope)
		if err != nil {
			return nil, err
		}
		if grant.TrustScope == TrustScopeDesktop && grant.ProfileDirectory != "" {
			return nil, errors.New("desktop Chrome trust cannot claim a profile directory")
		}
		if grant.TrustScope == TrustScopeProfile && !config.FixtureEnrollment && (!filepath.IsAbs(grant.ProfileDirectory) || filepath.Clean(grant.ProfileDirectory) != grant.ProfileDirectory) {
			return nil, errors.New("operator-pinned canonical Chrome profile directory required")
		}
		if !regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`).MatchString(grant.ProfileChannel) || !regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`).MatchString(grant.BrowserInstance) {
			return nil, errors.New("Bounded profile/browser identifiers required")
		}
		if grant.Principal.Validate() != nil || (!grant.Principal.HasScope("desktop:observe") && !grant.Principal.HasScope("desktop:control")) || grant.ProfileChannel == "" || grant.BrowserInstance == "" || !regexp.MustCompile(`^chrome-extension://[a-p]{32}/$`).MatchString(grant.ExtensionOrigin) || len(grant.Origins) == 0 || len(credentials[key]) < 32 || len(credentials[key]) > 4096 || b.channels[key] != nil {
			return nil, errors.New("invalid or duplicate Chrome enrollment")
		}
		for _, origin := range grant.Origins {
			parsed, e := url.Parse(origin)
			if e != nil || parsed.Host == "" || strings.ContainsAny(origin, "*\\") || parsed.Scheme+"://"+parsed.Host != origin || parsed.User != nil || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1"))) {
				return nil, errors.New("exact HTTPS or loopback origin required")
			}
		}
		grant.Principal.Scopes = append([]string(nil), grant.Principal.Scopes...)
		grant.Origins = append([]string(nil), grant.Origins...)
		encoded, _ := json.Marshal([]any{grant.Principal.Namespace, grant.ProfileChannel, grant.BrowserInstance, grant.ExtensionOrigin, grant.Origins, grant.ProfileDirectory, grant.TrustScope})
		hash := sha256.Sum256(encoded)
		b.channels[key] = &channel{fixtureOnly: config.FixtureEnrollment, profileQualified: config.FixtureEnrollment && grant.TrustScope == TrustScopeProfile, scopeQualified: config.FixtureEnrollment, executorQualified: config.FixtureEnrollment, grant: grant, credential: credentials[key], epoch: newID(), scopeHash: hex.EncodeToString(hash[:]), pending: map[string]*pending{}, attempts: map[string]Command{}, receipts: map[string]Reply{}, unknown: map[string]bool{}}
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: config.SocketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	b.listener = listener
	if err = os.Chmod(config.SocketPath, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	b.wg.Add(1)
	go b.accept()
	return b, nil
}
func (b *Broker) accept() {
	defer b.wg.Done()
	for {
		conn, err := b.listener.AcceptUnix()
		if err != nil {
			return
		}
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			conn.Close()
			return
		}
		b.connections[conn] = true
		b.wg.Add(1)
		b.mu.Unlock()
		go b.serve(conn)
	}
}
func allowedOrigin(grant Enrollment, origin string) bool {
	for _, allowed := range grant.Origins {
		if allowed == origin {
			return true
		}
	}
	return false
}
func (b *Broker) serve(conn net.Conn) {
	defer b.wg.Done()
	defer conn.Close()
	defer func() {
		b.mu.Lock()
		delete(b.connections, conn)
		for _, c := range b.channels {
			if c.conn == conn {
				c.conn = nil
				c.processEvidence = nil
				c.executorQualified = c.fixtureOnly
				c.profileQualified = c.fixtureOnly && c.grant.TrustScope == TrustScopeProfile
				c.scopeQualified = c.fixtureOnly
				c.documents = nil
				c.inventoryComplete = false
				for id, p := range c.pending {
					if p.mutation {
						c.unknown[p.command.AttemptID] = true
					}
					select {
					case p.done <- Reply{Error: browserError("hostLost", "Chrome host disconnected; reconcile original attempt", uncertain(p.mutation))}:
					default:
					}
					delete(c.pending, id)
				}
			}
		}
		b.mu.Unlock()
	}()
	var processEvidence *nativepeer.ChromeProcessEvidence
	if b.verifyPeer != nil {
		unix, ok := conn.(*net.UnixConn)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		evidence, err := b.verifyPeer(ctx, unix)
		cancel()
		if err != nil || !evidence.KernelPeerQualified {
			return
		}
		// Do not adopt profile/executor claims from any process verifier.
		evidence.ProfileQualified = false
		evidence.ExecutorQualified = false
		processEvidence = &evidence
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, err := ReadFrame(conn)
	if err != nil {
		return
	}
	var hello struct {
		Type                   string `json:"type"`
		ProtocolVersion        int    `json:"protocolVersion"`
		ProfileChannel         string `json:"profileChannel"`
		BrowserInstance        string `json:"browserInstance"`
		ExtensionOrigin        string `json:"extensionOrigin"`
		Credential             string `json:"credential"`
		FixtureEnrollment      bool   `json:"fixtureEnrollment"`
		ProfileDirectory       string `json:"profileDirectory"`
		ProfileLaunchQualified bool   `json:"profileLaunchQualified"`
		TrustScope             string `json:"trustScope"`
		ProfileQualified       *bool  `json:"profileQualified"`
	}
	if json.Unmarshal(data, &hello) != nil || hello.Type != "hello" || hello.ProtocolVersion != 1 {
		return
	}
	helloScope, err := NormalizeTrustScope(hello.TrustScope)
	if err != nil {
		return
	}
	b.mu.Lock()
	c := b.channels[channelKey(hello.ProfileChannel, hello.BrowserInstance)]
	if c == nil || helloScope != c.grant.TrustScope || c.fixtureOnly != hello.FixtureEnrollment || !c.fixtureOnly && processEvidence == nil || c.grant.ExtensionOrigin != hello.ExtensionOrigin || subtle.ConstantTimeCompare([]byte(c.credential), []byte(hello.Credential)) != 1 || c.conn != nil || b.closed {
		b.mu.Unlock()
		return
	}
	if helloScope == TrustScopeDesktop && (hello.ProfileLaunchQualified || hello.ProfileDirectory != "" || hello.ProfileQualified != nil && *hello.ProfileQualified || !c.fixtureOnly && !desktopProcessQualified(processEvidence)) {
		b.mu.Unlock()
		return
	}
	if helloScope == TrustScopeProfile && !c.fixtureOnly && (!hello.ProfileLaunchQualified || hello.ProfileDirectory == "" || hello.ProfileDirectory != c.grant.ProfileDirectory || len(processEvidence.Ancestors) != 1 || processEvidence.Ancestors[0] != processEvidence.ChromeParent) {
		b.mu.Unlock()
		return
	}
	c.conn = conn
	c.processEvidence = processEvidence
	c.profileQualified = helloScope == TrustScopeProfile
	c.scopeQualified = true
	c.executorQualified = c.fixtureOnly
	c.executorChallenge = newID()
	b.mu.Unlock()
	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	acknowledgement := "enrolled"
	if !c.fixtureOnly {
		acknowledgement = "processQualified"
	}
	if WriteFrame(conn, map[string]any{"type": acknowledgement, "brokerEpoch": b.epoch, "channelEpoch": c.epoch, "scopeHash": c.scopeHash, "trustScope": c.grant.TrustScope, "scopeQualified": c.scopeQualified, "profileQualified": c.profileQualified, "executorQualified": c.executorQualified, "executorChallenge": c.executorChallenge, "mutationFingerprintVersion": 2, "fixtureOnly": c.fixtureOnly}) != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Time{})
	count, total := 0, 0
	for {
		data, err = ReadFrame(conn)
		if err != nil {
			return
		}
		count++
		total += len(data)
		if count > 65536 || total > 64*1024*1024 {
			return
		}
		var event struct {
			Type                       string          `json:"type"`
			MutationFingerprintVersion int             `json:"mutationFingerprintVersion"`
			Documents                  []Document      `json:"documents"`
			Truncated                  bool            `json:"truncated"`
			ExecutorChallenge          string          `json:"executorChallenge"`
			Error                      json.RawMessage `json:"error"`
		}
		if json.Unmarshal(data, &event) != nil {
			return
		}
		b.mu.Lock()
		if event.Type == "attention" {
			var attention struct {
				Code string `json:"code"`
			}
			if json.Unmarshal(event.Error, &attention) != nil {
				attention.Code = ""
			}
			c.attentionCode = browserAttentionCode(attention.Code)
			// Worker attention withdraws executor readiness; existing pending
			// receipts and unknown attempts remain available for reconciliation.
			c.executorQualified = false
			c.documents = nil
			c.inventoryComplete = false
			b.mu.Unlock()
			continue
		}
		if event.Type == "executorPrepared" {
			// The trusted worker acknowledges this connection-specific server fence
			// only after every eligible root document accepts the same immutable binding.
			if c.lifecycleInhibited {
				b.mu.Unlock()
				continue
			}
			if c.fixtureOnly || event.ExecutorChallenge != c.executorChallenge || len(c.unknown) != 0 || len(c.pending) != 0 {
				b.mu.Unlock()
				return
			}
			if event.MutationFingerprintVersion != 0 && event.MutationFingerprintVersion != 1 && event.MutationFingerprintVersion != 2 {
				b.mu.Unlock()
				return
			}
			c.mutationFingerprintVersion = event.MutationFingerprintVersion
			c.executorQualified = true
			c.attentionCode = ""
			b.mu.Unlock()
			continue
		}
		if event.Type == "documents" {
			if !channelScopeQualified(c) || (!c.executorQualified && !c.lifecycleInhibited) {
				c.documents = nil
				c.inventoryComplete = false
				b.mu.Unlock()
				continue
			}
			if event.Truncated || len(event.Documents) > 200 {
				c.documents = nil
				c.inventoryComplete = false
				b.mu.Unlock()
				continue
			}
			valid := true
			for _, d := range event.Documents {
				if d.MutationFingerprintVersion != 0 && d.MutationFingerprintVersion != 1 && d.MutationFingerprintVersion != 2 || d.MutationFingerprintVersion == 2 && c.mutationFingerprintVersion != 2 || d.ProfileChannel != c.grant.ProfileChannel || d.BrowserInstance != c.grant.BrowserInstance || d.DocumentID == "" || d.Generation == 0 || d.TabID < 0 || d.FrameID < 0 || !allowedOrigin(c.grant, d.Origin) || len(d.Title) > 1024 {
					valid = false
					break
				}
			}
			if valid {
				for i := range event.Documents {
					event.Documents[i].TabHandle = event.Documents[i].QualifiedTabID()
				}
				c.documents = append([]Document(nil), event.Documents...)
				c.inventoryComplete = true
				c.inventoryAt = time.Now()
			} else {
				c.documents = nil
				c.inventoryComplete = false
			}
			b.mu.Unlock()
			continue
		}
		var reply Reply
		if json.Unmarshal(data, &reply) != nil {
			b.mu.Unlock()
			return
		}
		p := c.pending[reply.RequestID]
		if p == nil {
			b.mu.Unlock()
			continue
		}
		if p.lifecycle != nil {
			valid := p.lifecycle.validLocked() && reply.RequestID == p.command.RequestID && reply.Identity.ProfileChannel == p.command.Identity.ProfileChannel && reply.Identity.BrowserInstance == p.command.Identity.BrowserInstance && reply.Identity.TabID == p.command.Identity.TabID && reply.Identity.FrameID == p.command.Identity.FrameID && reply.Identity.DocumentID == p.command.Identity.DocumentID && reply.Identity.Generation >= p.command.Identity.Generation && reply.Error == nil
			response := lifecycleReply{raw: append(json.RawMessage(nil), data...)}
			if !valid {
				response = lifecycleReply{err: ErrLifecycleReceiptAuthority}
			}
			delete(c.pending, p.command.RequestID)
			select {
			case p.lifecycleDone <- response:
			default:
			}
			b.mu.Unlock()
			continue
		}
		valid := reply.Identity.ProfileChannel == p.command.Identity.ProfileChannel && reply.Identity.BrowserInstance == p.command.Identity.BrowserInstance && reply.Identity.TabID == p.command.Identity.TabID && reply.Identity.FrameID == p.command.Identity.FrameID && reply.Identity.DocumentID == p.command.Identity.DocumentID && reply.Identity.Generation >= p.command.Identity.Generation
		if !p.mutation && reply.Error != nil && reply.Error.DispatchState == "notDispatched" && reply.Identity.DocumentID == "" {
			valid = true
		}
		if p.mutation && p.command.FingerprintVersion == 2 {
			valid = valid && reply.FingerprintVersion == 2 && reply.FingerprintSHA256 == p.command.FingerprintSHA256
		}
		if p.mutation {
			valid = valid && reply.AttemptID == p.command.AttemptID && (reply.DispatchState == "dispatched" || reply.DispatchState == "notDispatched" || reply.Error != nil && reply.Error.DispatchState == "notDispatched")
			if reply.NewDocument != nil {
				d := reply.NewDocument
				valid = valid && d.ProfileChannel == p.command.Identity.ProfileChannel && d.BrowserInstance == p.command.Identity.BrowserInstance && d.TabID == p.command.Identity.TabID && d.FrameID == 0 && d.DocumentID != "" && d.Generation > 0 && allowedOrigin(c.grant, d.Origin)
			}
		}
		if !valid {
			reply = Reply{Error: browserError("receiptMismatch", "Reply identity mismatched; reconcile original attempt", uncertain(p.mutation))}
			if p.mutation {
				c.unknown[p.command.AttemptID] = true
			}
		} else {
			for i, d := range c.documents {
				if d.DocumentID == reply.Identity.DocumentID && d.TabID == reply.Identity.TabID {
					c.documents[i].Generation = reply.Identity.Generation
				}
			}
			if p.mutation {
				if reply.EffectState != "unknown" && (reply.Error == nil || reply.Error.DispatchState != "unknown") {
					c.receipts[p.command.AttemptID] = reply
					delete(c.unknown, p.command.AttemptID)
				} else {
					c.unknown[p.command.AttemptID] = true
				}
			}
			if p.command.Action == "receipt.query" && reply.AttemptID == p.command.AttemptID && (reply.DispatchState == "dispatched" || reply.DispatchState == "notDispatched") && reply.EffectState != "unknown" && (reply.Error == nil || reply.Error.DispatchState != "unknown") {
				c.receipts[p.command.AttemptID] = reply
				delete(c.unknown, p.command.AttemptID)
			}
		}
		delete(c.pending, p.command.RequestID)
		select {
		case p.done <- reply:
		default:
		}
		b.mu.Unlock()
	}
}
func uncertain(mutation bool) string {
	if mutation {
		return "unknown"
	}
	return "notDispatched"
}
func (b *Broker) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	for conn := range b.connections {
		conn.Close()
	}
	b.mu.Unlock()
	err := b.listener.Close()
	b.wg.Wait()
	return err
}
