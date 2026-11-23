package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// Defaults of the VLESS dataplane. The listen port is the one inside the pod;
// the port clients use is PublicPort, which the Service and traefik publish.
const (
	DefaultVLESSListenPort = 10443
	DefaultVLESSAPIPort    = 10085
	// DefaultVLESSFlow is what Xray calls its Vision flow, the one AmneziaVPN
	// uses for a REALITY server. It is what makes the connection behave like
	// the TLS stream it pretends to be.
	DefaultVLESSFlow        = "xtls-rprx-vision"
	DefaultVLESSFingerprint = "firefox"
	// DefaultVLESSLogLevel is quiet enough for production and still reports a
	// process that cannot start or a configuration it rejects. "info" adds
	// one line per accepted connection, which is how a client that never
	// dials is told apart from one whose handshake fails.
	DefaultVLESSLogLevel = "warning"
	// vlessCoverPort is the port REALITY is pointed at on the cover host. It
	// is not the listening port: the server looks like a connection to the
	// cover site's HTTPS.
	vlessCoverPort = 443
)

// VLESSConfig is the second protocol: VLESS over REALITY, served by Xray.
//
// It is off unless enabled, and then three things have to be configured: where
// clients reach it (PublicHost/PublicPort), what it pretends to be (CoverHost)
// and the server's REALITY key pair, of which only the private half is stored -
// the public half is derived, so the two can never disagree.
//
// One property of REALITY is worth knowing when reading the rest of the code:
// the cover host is part of the TLS handshake (the client sends it as the SNI)
// and part of the routing in front of the server (traefik matches it). Changing
// it therefore means changing the proxy rule and reissuing every configuration,
// exactly like changing the key.
type VLESSConfig struct {
	// Enabled turns the VLESS dataplane on. The WireGuard one is unaffected
	// either way.
	Enabled bool `yaml:"enabled"`
	// Binary is the Xray executable. Defaults to "xray" from the PATH.
	Binary string `yaml:"binary"`
	// ListenPort is the port Xray listens on inside the container. It is not
	// published; the Service maps the public port to it.
	ListenPort int `yaml:"listenPort"`
	// APIPort is the loopback port of Xray's management API, which is how
	// users are added and removed without restarting the process, and how
	// their traffic is read.
	APIPort int `yaml:"apiPort"`
	// PublicHost is the name clients show for this server. It is the name in
	// DNS, not the cover host: clients resolve it to this server and then
	// present the cover host as the SNI. When PublicIP is empty, this is also
	// what client configurations dial.
	//
	// It is the name a person reads, which is why it stays a name even when
	// PublicIP is set. Either this or PublicIP has to be set.
	PublicHost string `yaml:"publicHost"`
	// PublicIP is what client configurations actually dial, when it is set.
	//
	// A name cannot be used by the mobile clients: AmneziaVPN starts its local
	// Xray inside the tunnel it just created, with the tunnel's own DNS
	// servers, so resolving the server's name needs the connection that
	// resolving it is for. An address breaks that circle. Leave it empty to
	// dial the name (fine for a client that resolves before the tunnel comes
	// up, and for a deployment whose address does not change).
	PublicIP string `yaml:"publicIP"`
	// PublicPort is the port clients connect to, normally 443.
	PublicPort int `yaml:"publicPort"`
	// CoverHost is the site the server pretends to be, and the value the
	// client sends as the SNI. It has to be a real HTTPS site: REALITY hands
	// its handshake to an unauthenticated client, so a prober has to end up
	// looking at that site's own certificate.
	CoverHost string `yaml:"coverHost"`
	// RealityPrivateKey is the server's REALITY private key, base64url
	// without padding, 32 bytes - what `xray x25519` prints as PrivateKey.
	// It is a secret: anyone who has it can impersonate this server.
	RealityPrivateKey string `yaml:"realityPrivateKey"`
	// ShortID is the REALITY short id, hex, at most 16 characters. It is not
	// secret, it is in every client configuration, but it has to be stable:
	// changing it invalidates every configuration that was handed out.
	ShortID string `yaml:"shortId"`
	// Flow is the VLESS flow. It defaults to DefaultVLESSFlow; REALITY needs a
	// flow, so it is never empty while the server is enabled.
	Flow string `yaml:"flow"`
	// Fingerprint is the uTLS fingerprint the client presents. It lives here
	// because it is part of the client configuration, not of the server.
	Fingerprint string `yaml:"fingerprint"`
	// LogLevel is what the Xray process writes to its own log. Warning is
	// enough to see failures; info also names every accepted connection,
	// which is what tells "the client never dialled" apart from "the client
	// dialled and the handshake failed".
	LogLevel string `yaml:"logLevel"`
}

// Validate applies the defaults and refuses a profile that could only produce
// client configurations that do not connect.
func (c *VLESSConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Binary == "" {
		c.Binary = "xray"
	}
	if c.ListenPort == 0 {
		c.ListenPort = DefaultVLESSListenPort
	}
	if c.APIPort == 0 {
		c.APIPort = DefaultVLESSAPIPort
	}
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return fmt.Errorf("vless.listenPort must be a port number, got %d", c.ListenPort)
	}
	if c.APIPort < 1 || c.APIPort > 65535 {
		return fmt.Errorf("vless.apiPort must be a port number, got %d", c.APIPort)
	}
	if c.ListenPort == c.APIPort {
		return fmt.Errorf("vless.listenPort and vless.apiPort must differ, both are %d", c.ListenPort)
	}
	if c.PublicPort == 0 {
		c.PublicPort = vlessCoverPort
	}
	if c.PublicPort < 1 || c.PublicPort > 65535 {
		return fmt.Errorf("vless.publicPort must be a port number, got %d", c.PublicPort)
	}
	if err := validateHostName("vless.publicHost", c.PublicHost, true); err != nil {
		return err
	}
	if c.PublicIP != "" {
		address, err := netip.ParseAddr(c.PublicIP)
		if err != nil || address.IsUnspecified() || address.IsLoopback() {
			return fmt.Errorf("vless.publicIP must be the address clients reach, got %q", c.PublicIP)
		}
	}
	if c.PublicHost == "" && c.PublicIP == "" {
		return fmt.Errorf("vless.publicHost or vless.publicIP is required: one of them is what client configurations dial")
	}
	if err := validateHostName("vless.coverHost", c.CoverHost, false); err != nil {
		return err
	}
	if c.CoverHost == c.PublicHost {
		// REALITY would relay the handshake to the server itself, and the
		// certificate a prober sees would be ours rather than a third
		// party's - the one thing the disguise must not look like.
		return fmt.Errorf("vless.coverHost must differ from vless.publicHost")
	}
	if _, err := c.publicKey(); err != nil {
		return err
	}
	if err := validateShortID(c.ShortID); err != nil {
		return err
	}
	if c.Flow == "" {
		c.Flow = DefaultVLESSFlow
	}
	if c.Flow != DefaultVLESSFlow && c.Flow != DefaultVLESSFlow+"-udp443" {
		return fmt.Errorf("vless.flow %q is not one of %q or %q", c.Flow, DefaultVLESSFlow, DefaultVLESSFlow+"-udp443")
	}
	if c.Fingerprint == "" {
		c.Fingerprint = DefaultVLESSFingerprint
	}
	if c.LogLevel == "" {
		c.LogLevel = DefaultVLESSLogLevel
	}
	switch c.LogLevel {
	case "debug", "info", "warning", "error":
	default:
		return fmt.Errorf("vless.logLevel must be one of debug, info, warning or error, got %q", c.LogLevel)
	}
	return nil
}

// PublicKey derives the REALITY public key from the configured private one.
// Clients need it; the server has no reason to store it.
func (c VLESSConfig) PublicKey() string {
	public, err := c.publicKey()
	if err != nil {
		return ""
	}
	return public
}

func (c VLESSConfig) publicKey() (string, error) {
	private, err := decodeBase64URL(c.RealityPrivateKey)
	if err != nil {
		return "", fmt.Errorf("vless.realityPrivateKey: %w", err)
	}
	if len(private) != curve25519.PointSize {
		return "", fmt.Errorf("vless.realityPrivateKey must be %d bytes, got %d", curve25519.PointSize, len(private))
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("vless.realityPrivateKey is not a valid X25519 key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(public), nil
}

// DialAddress is what client configurations dial: the configured address when
// there is one, otherwise the name. The difference matters for the mobile
// clients, see PublicIP.
func (c VLESSConfig) DialAddress() string {
	if c.PublicIP != "" {
		return c.PublicIP
	}
	return c.PublicHost
}

// Dest is what REALITY forwards an unauthenticated handshake to: the cover
// site's own HTTPS port.
func (c VLESSConfig) Dest() string {
	return net.JoinHostPort(c.CoverHost, fmt.Sprint(vlessCoverPort))
}

// ServerName is the SNI the server accepts, which is the cover host.
func (c VLESSConfig) ServerName() string {
	return c.CoverHost
}

// decodeBase64URL accepts what the Xray tools print, with or without padding.
func decodeBase64URL(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, fmt.Errorf("is empty")
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(trimmed); err == nil {
		return decoded, nil
	}
	decoded, err := base64.URLEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("is not base64url: %w", err)
	}
	return decoded, nil
}

// validateShortID mirrors what Xray accepts: hexadecimal, even length, at most
// eight bytes. An empty value is legal in Xray, but a stable one is better - it
// is what keeps an old client configuration working.
func validateShortID(value string) error {
	if value == "" {
		return fmt.Errorf("vless.shortId is required: generate one with `openssl rand -hex 8`")
	}
	if len(value) > 16 {
		return fmt.Errorf("vless.shortId must be at most 16 hexadecimal characters, got %d", len(value))
	}
	if len(value)%2 != 0 {
		return fmt.Errorf("vless.shortId must have an even number of hexadecimal characters, got %d", len(value))
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("vless.shortId is not hexadecimal: %w", err)
	}
	return nil
}

// validateHostName checks a bare host name: no scheme, no port, no path. It is
// what the configuration has to hold; a URL pasted from a browser is a mistake
// that would otherwise end up inside a client configuration.
func validateHostName(setting, value string, optional bool) error {
	if value == "" {
		if optional {
			return nil
		}
		return fmt.Errorf("%s is required", setting)
	}
	if strings.Contains(value, "://") {
		return fmt.Errorf("%s must be a host name without a scheme, got %q", setting, value)
	}
	if strings.ContainsAny(value, "/?#") {
		return fmt.Errorf("%s must be a host name without a path, got %q", setting, value)
	}
	if _, _, err := net.SplitHostPort(value); err == nil {
		return fmt.Errorf("%s must be a host name without a port, got %q", setting, value)
	}
	if strings.Contains(value, " ") || strings.Contains(value, ":") {
		return fmt.Errorf("%s must be a host name, got %q", setting, value)
	}
	return nil
}
