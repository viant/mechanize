// mechanize-native-host is a framed authenticated bridge, with no input authority.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/scy"
	_ "github.com/viant/scy/kms/blowfish" // Register operator-selected encrypted env-key enrollment.
)

// embeddedBrokerRequirement is set by the trusted builder with -ldflags -X
// before signing this image. Empty development binaries cannot use production.
var embeddedBrokerRequirement string

type Config struct {
	SocketPath         string       `json:"socketPath"`
	ExtensionOrigin    string       `json:"extensionOrigin"`
	ProfileChannel     string       `json:"profileChannel"`
	BrowserInstance    string       `json:"browserInstance"`
	CredentialResource scy.Resource `json:"credentialResource"`
	// Until signed-parent/audit-token enrollment is qualified, fixture-only must
	// be explicitly enabled in both the host configuration and broker enrollment.
	FixtureEnrollment bool                            `json:"fixtureEnrollment"`
	ProcessTrust      *nativepeer.ChromeProcessPolicy `json:"processTrust,omitempty"`
	BrokerRequirement string                          `json:"brokerRequirement,omitempty"`
	ProfileDirectory  string                          `json:"profileDirectory,omitempty"`
	TrustScope        string                          `json:"trustScope,omitempty"`
	processQualified  bool
	profileQualified  bool
}

func loadConfig(path, origin string) (*Config, error) {
	if err := validatePrivateFile(path); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	config := &Config{}
	decoder := json.NewDecoder(io.LimitReader(file, 16385))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(config); err != nil {
		return nil, errors.New("invalid host configuration")
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing host configuration")
	}
	if _, err := configuredTrustScope(config); err != nil {
		return nil, err
	}
	if config.FixtureEnrollment {
		if config.ProcessTrust != nil || config.BrokerRequirement != "" {
			return nil, errors.New("fixture and production host trust cannot be combined")
		}
	} else {
		if err := validateEmbeddedBrokerRequirement(config); err != nil {
			return nil, err
		}
		fixed, err := defaultConfigPath()
		if err != nil || path != fixed || os.Getenv("MECHANIZE_NATIVE_HOST_CONFIG") != "" {
			return nil, errors.New("production native host requires its fixed private operator configuration")
		}
		if config.ProcessTrust == nil || config.BrokerRequirement == "" {
			return nil, errors.New("production parent/signature enrollment is not qualified; host disabled")
		}
	}
	if config.ExtensionOrigin != origin || !regexp.MustCompile(`^chrome-extension://[a-p]{32}/$`).MatchString(origin) {
		return nil, errors.New("extension origin is not enrolled")
	}
	if config.ProfileChannel == "" || config.BrowserInstance == "" || !filepath.IsAbs(config.SocketPath) {
		return nil, errors.New("missing fixed channel/socket identity")
	}
	if config.CredentialResource.URL == "" || config.CredentialResource.Key == "" || config.CredentialResource.Fallback != nil || len(config.CredentialResource.Data) != 0 {
		return nil, errors.New("encrypted Scy credential resource with no fallback required")
	}
	return config, nil
}

// Bridge exchanges one enrollment hello and then forwards each frame once. It
// never reconnects/replays commands, evaluates input, or owns a mutation lease.
func Bridge(chromeReader io.Reader, chromeWriter io.Writer, broker net.Conn, config *Config, credential string) error {
	trustScope, err := configuredTrustScope(config)
	if err != nil {
		return err
	}
	if !config.FixtureEnrollment && (!config.processQualified || trustScope == "profile" && (!config.profileQualified || config.ProfileDirectory == "")) {
		return errors.New("production process/channel proof required before bridge")
	}
	message, err := ReadFrame(chromeReader)
	if err != nil {
		return err
	}
	var hello map[string]json.RawMessage
	if err = json.Unmarshal(message, &hello); err != nil {
		return errors.New("invalid hello")
	}
	var kind, profile, instance string
	var version int
	_ = json.Unmarshal(hello["type"], &kind)
	_ = json.Unmarshal(hello["profileChannel"], &profile)
	_ = json.Unmarshal(hello["browserInstance"], &instance)
	_ = json.Unmarshal(hello["protocolVersion"], &version)
	if kind != "hello" || version != 1 || profile != config.ProfileChannel || instance != config.BrowserInstance || credential == "" {
		return errors.New("channel identity mismatch")
	}
	// Host-owned fields override untrusted extension payload values.
	hello["credential"], _ = json.Marshal(credential)
	hello["extensionOrigin"], _ = json.Marshal(config.ExtensionOrigin)
	hello["fixtureEnrollment"], _ = json.Marshal(config.FixtureEnrollment)
	hello["trustScope"], _ = json.Marshal(trustScope)
	hello["profileDirectory"], _ = json.Marshal(config.ProfileDirectory)
	hello["profileLaunchQualified"], _ = json.Marshal(!config.FixtureEnrollment && trustScope == "profile" && config.profileQualified)
	message, err = json.Marshal(hello)
	if err != nil {
		return err
	}
	if err = WriteFrame(broker, message); err != nil {
		return err
	}
	completed := make(chan error, 2)
	copyFrames := func(reader io.Reader, writer io.Writer) {
		count := 0
		totalBytes := 0
		for {
			frame, e := ReadFrame(reader)
			if e != nil {
				completed <- e
				return
			}
			count++
			totalBytes += len(frame)
			if count > 65536 || totalBytes > 64*1024*1024 {
				completed <- errors.New("channel frame quota exhausted")
				return
			}
			var payload map[string]json.RawMessage
			if json.Unmarshal(frame, &payload) != nil {
				completed <- errors.New("object frame required")
				return
			}
			// Enrollment credentials appear only in the one host-originated hello.
			if _, exists := payload["credential"]; exists {
				completed <- errors.New("credential field forbidden after enrollment")
				return
			}
			if e = WriteFrame(writer, frame); e != nil {
				completed <- e
				return
			}
		}
	}
	go copyFrames(chromeReader, broker)
	go copyFrames(broker, chromeWriter)
	err = <-completed
	_ = broker.Close()
	return err
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("Chrome extension origin argument required")
	}
	path, err := defaultConfigPath()
	if err != nil {
		return err
	}
	if fixturePath := os.Getenv("MECHANIZE_NATIVE_HOST_CONFIG"); fixturePath != "" {
		path = fixturePath
	}
	config, err := loadConfig(path, os.Args[1])
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Check the local process before opening the endpoint. No credential may be
	// loaded until the actual reverse Unix peer is independently authenticated.
	evidence, err := verifyHostProcess(ctx, config)
	if err != nil {
		return err
	}
	if err := qualifyLaunchScope(config, evidence, os.Args); err != nil {
		return err
	}
	if config.FixtureEnrollment {
		info, err := os.Lstat(config.SocketPath)
		if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0077 != 0 {
			return errors.New("fixture broker socket must be private")
		}
	} else if err = validateBrokerSocket(config.SocketPath, config.ProcessTrust.ExpectedUID); err != nil {
		return err
	}
	broker, err := net.DialTimeout("unix", config.SocketPath, 5*time.Second)
	if err != nil {
		return errors.New("broker unavailable")
	}
	defer broker.Close()
	credential, err := authenticatedCredential(ctx, config, broker, verifyHostProcess, verifyBrokerPeer, func() (string, error) {
		secret, err := scy.New().Load(ctx, &config.CredentialResource)
		if err != nil {
			return "", errors.New("Scy enrollment credential unavailable")
		}
		credential := strings.TrimSpace(secret.String())
		if len(credential) < 32 || len(credential) > 4096 || bytes.ContainsAny([]byte(credential), "\r\n") {
			return "", errors.New("invalid enrollment credential")
		}
		return credential, nil
	})
	if err != nil {
		return err
	}
	return Bridge(os.Stdin, os.Stdout, broker, config, credential)
}

func main() {
	if err := run(); err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintln(os.Stderr, "Mechanize native transport:", err)
		os.Exit(1)
	}
}
