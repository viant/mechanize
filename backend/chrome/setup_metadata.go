package chrome

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/session"
)

var errSetupMetadata = errors.New("authenticated Chrome setup metadata unavailable")
var setupHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

type SetupMetadata struct {
	Version                  int    `json:"version"`
	ExtensionID              string `json:"extensionId"`
	ExtensionVersion         string `json:"extensionVersion"`
	StorageSHA256            string `json:"storageSHA256"`
	StorageScope             string `json:"storageScope"`
	StorageStable            bool   `json:"storageStable"`
	ActiveCommands           int    `json:"activeCommands"`
	UnknownAttempts          int    `json:"unknownAttempts"`
	MutationBusy             bool   `json:"mutationBusy"`
	LifecycleInhibited       bool   `json:"lifecycleInhibited"`
	NativeConnected          bool   `json:"nativeConnected"`
	ExecutorQualified        bool   `json:"executorQualified"`
	LoadedDirectoryAvailable bool   `json:"loadedDirectoryAvailable"`
}
type setupMetadataRequest struct {
	Type           string `json:"type"`
	RequestID      string `json:"requestId"`
	Nonce          string `json:"nonce"`
	BrokerEpoch    string `json:"brokerEpoch"`
	ChannelEpoch   string `json:"channelEpoch"`
	ScopeHash      string `json:"scopeHash"`
	DeadlineUnixMS int64  `json:"deadlineUnixMs"`
}
type setupMetadataReply struct {
	Type         string        `json:"type"`
	RequestID    string        `json:"requestId"`
	Nonce        string        `json:"nonce"`
	BrokerEpoch  string        `json:"brokerEpoch"`
	ChannelEpoch string        `json:"channelEpoch"`
	ScopeHash    string        `json:"scopeHash"`
	Metadata     SetupMetadata `json:"metadata"`
}
type setupMetadataPending struct {
	request setupMetadataRequest
	conn    net.Conn
	done    chan setupMetadataReply
}

// Native/Chrome process provenance belongs to the broker, never extension JSON.
// The digest/worker flags describe a sample, not stopped processes or a loaded
// filesystem directory. Those require independent native-workflow receipts.
type BrowserSetupMetadataReceipt struct {
	Metadata              SetupMetadata           `json:"metadata"`
	ProfileChannel        string                  `json:"profileChannel"`
	BrowserInstance       string                  `json:"browserInstance"`
	BrokerEpoch           string                  `json:"brokerEpoch"`
	ChannelEpoch          string                  `json:"channelEpoch"`
	ScopeHash             string                  `json:"scopeHash"`
	NativeHost            session.ProcessIdentity `json:"nativeHost"`
	ChromeParent          session.ProcessIdentity `json:"chromeParent"`
	NativeHostRequirement string                  `json:"nativeHostRequirement"`
	ChromeRequirement     string                  `json:"chromeRequirement"`
	BrokerPending         int                     `json:"brokerPending"`
	BrokerUnknown         int                     `json:"brokerUnknown"`
	ObservedAt            time.Time               `json:"observedAt"`
	ReceiptSHA256         string                  `json:"receiptSHA256"`
	MissingEvidence       []string                `json:"missingEvidence"`
}

// Opaque in-process origin proof; serialized receipt hashes alone confer no trust.
type BrowserSetupMetadataProof struct {
	broker          *Broker
	channel         *channel
	conn            net.Conn
	owner, clientID string
	receipt         BrowserSetupMetadataReceipt
}

func (p BrowserSetupMetadataProof) Metadata() BrowserSetupMetadataReceipt {
	r := p.receipt
	r.MissingEvidence = append([]string(nil), r.MissingEvidence...)
	return r
}

func validSetupMetadata(m SetupMetadata, extension string) bool {
	return m.Version == 1 && "chrome-extension://"+m.ExtensionID+"/" == extension && regexp.MustCompile(`^[a-p]{32}$`).MatchString(m.ExtensionID) && regexp.MustCompile(`^\d+(\.\d+){0,3}$`).MatchString(m.ExtensionVersion) && len(m.ExtensionVersion) <= 32 && setupHash.MatchString(m.StorageSHA256) && m.StorageScope == "extension-local-v1" && m.StorageStable && m.ActiveCommands >= 0 && m.ActiveCommands <= 4096 && m.UnknownAttempts >= 0 && m.UnknownAttempts <= 4096 && m.NativeConnected && !m.LoadedDirectoryAvailable
}

// Called under the broker mutex. No document/grant/unknown state is changed.
func (b *Broker) acceptSetupMetadata(c *channel, data []byte) {
	p := c.setupPending
	if p == nil || p.conn != c.conn || len(data) > 4096 {
		return
	}
	var response setupMetadataReply
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&response) != nil || decoder.Decode(new(any)) != io.EOF {
		return
	}
	canonical, _ := json.Marshal(response)
	r := p.request
	if !bytes.Equal(canonical, data) || response.Type != "setupMetadata" || response.RequestID != r.RequestID || response.Nonce != r.Nonce || response.BrokerEpoch != r.BrokerEpoch || response.ChannelEpoch != r.ChannelEpoch || response.ScopeHash != r.ScopeHash || time.Now().UnixMilli() > r.DeadlineUnixMS || !validSetupMetadata(response.Metadata, c.grant.ExtensionOrigin) {
		return
	}
	select {
	case p.done <- response:
	default:
	}
}
func (g *Gateway) SetupMetadata(ctx context.Context, p auth.Principal, profile, browser string) (BrowserSetupMetadataProof, error) {
	if err := authorize(ctx, p, false); err != nil {
		return BrowserSetupMetadataProof{}, err
	}
	actual, _ := auth.FromContext(ctx)
	if actual.ClientID != p.ClientID {
		return BrowserSetupMetadataProof{}, auth.ErrUnauthorized
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ctx = bounded
	b := g.broker
	b.mu.Lock()
	c := b.channels[channelKey(profile, browser)]
	if c == nil || c.grant.Principal.Namespace != p.Namespace || c.fixtureOnly || !c.setupAvailable || c.conn == nil || !channelScopeQualified(c) || c.setupPending != nil || b.processTrust == nil {
		b.mu.Unlock()
		return BrowserSetupMetadataProof{}, errSetupMetadata
	}
	b.mu.Unlock()
	if b.checkChannelProcess(ctx, c, false) != nil {
		return BrowserSetupMetadataProof{}, errSetupMetadata
	}
	deadline, _ := ctx.Deadline()
	b.mu.Lock()
	if b.closed || c.conn == nil || !c.setupAvailable || c.setupPending != nil {
		b.mu.Unlock()
		return BrowserSetupMetadataProof{}, errSetupMetadata
	}
	pending := &setupMetadataPending{request: setupMetadataRequest{Type: "setupMetadata", RequestID: newID() + newID(), Nonce: newID() + newID(), BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, DeadlineUnixMS: deadline.UnixMilli()}, conn: c.conn, done: make(chan setupMetadataReply, 1)}
	c.setupPending = pending
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		if c.setupPending == pending {
			c.setupPending = nil
		}
		b.mu.Unlock()
	}()
	written := make(chan error, 1)
	go func() {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		if ctx.Err() != nil {
			written <- errSetupMetadata
			return
		}
		b.mu.Lock()
		same := c.conn == pending.conn && c.setupPending == pending && !b.closed
		b.mu.Unlock()
		if !same || b.checkChannelProcess(ctx, c, false) != nil {
			written <- errSetupMetadata
			return
		}
		pending.conn.SetWriteDeadline(deadline)
		err := WriteFrame(pending.conn, pending.request)
		pending.conn.SetWriteDeadline(time.Time{})
		written <- err
	}()
	select {
	case err := <-written:
		if err != nil {
			return BrowserSetupMetadataProof{}, errSetupMetadata
		}
	case <-ctx.Done():
		return BrowserSetupMetadataProof{}, errSetupMetadata
	}
	var reply setupMetadataReply
	select {
	case reply = <-pending.done:
	case <-ctx.Done():
		return BrowserSetupMetadataProof{}, errSetupMetadata
	}
	if b.checkChannelProcess(ctx, c, false) != nil {
		return BrowserSetupMetadataProof{}, errSetupMetadata
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if c.conn != pending.conn || b.closed || c.epoch != pending.request.ChannelEpoch || c.scopeHash != pending.request.ScopeHash || b.epoch != pending.request.BrokerEpoch || c.processEvidence == nil || !channelScopeQualified(c) {
		return BrowserSetupMetadataProof{}, errSetupMetadata
	}
	receipt := BrowserSetupMetadataReceipt{Metadata: reply.Metadata, ProfileChannel: profile, BrowserInstance: browser, BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, NativeHost: c.processEvidence.NativeHost, ChromeParent: c.processEvidence.ChromeParent, NativeHostRequirement: b.processTrust.NativeHostRequirement, ChromeRequirement: b.processTrust.ChromeRequirement, BrokerPending: len(c.pending), BrokerUnknown: len(c.unknown), ObservedAt: time.Now().UTC(), MissingEvidence: []string{"nativeLoadedDirectoryReceipt", "brokerAndConsoleProcessPins", "stoppedProcessReceipts", "executorQuiescenceReceipt"}}
	raw, _ := json.Marshal(receipt)
	digest := sha256.Sum256(raw)
	receipt.ReceiptSHA256 = hex.EncodeToString(digest[:])
	return BrowserSetupMetadataProof{broker: b, channel: c, conn: c.conn, owner: p.Namespace, clientID: p.ClientID, receipt: receipt}, nil
}
func (g *Gateway) VerifySetupMetadata(ctx context.Context, p auth.Principal, proof BrowserSetupMetadataProof) error {
	actual, _ := auth.FromContext(ctx)
	if actual.ClientID != p.ClientID {
		return errSetupMetadata
	}
	if authorize(ctx, p, false) != nil || proof.broker != g.broker || proof.channel == nil || proof.owner != p.Namespace || proof.clientID != p.ClientID || proof.receipt.ObservedAt.After(time.Now()) || time.Since(proof.receipt.ObservedAt) > 30*time.Second {
		return errSetupMetadata
	}
	if g.broker.checkChannelProcess(ctx, proof.channel, false) != nil {
		return errSetupMetadata
	}
	b := g.broker
	b.mu.Lock()
	defer b.mu.Unlock()
	c := proof.channel
	if c.conn != proof.conn || b.closed || c.epoch != proof.receipt.ChannelEpoch || c.scopeHash != proof.receipt.ScopeHash || b.epoch != proof.receipt.BrokerEpoch || c.processEvidence == nil || c.processEvidence.NativeHost != proof.receipt.NativeHost || c.processEvidence.ChromeParent != proof.receipt.ChromeParent {
		return errSetupMetadata
	}
	return nil
}
