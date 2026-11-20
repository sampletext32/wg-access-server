package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/sampletext32/amneziawg-embed/pkg/wgembed"
)

// AmneziaConfig is the AmneziaWG profile of this server. Unlike WireGuard, its
// obfuscation parameters must agree between the server and every client, so
// the same block feeds both: the server's interface and every client
// configuration file get the shared values, each client additionally gets the
// values that only shape its own packets, and the header protection key.
//
// An empty block means the server speaks plain WireGuard. That is what a
// WireGuard server does, and it is also the safe state for a development
// instance, but it is detectable - the server says so at startup.
type AmneziaConfig struct {
	// Server holds values that are kept like a secret on the server, but are
	// not per-client: every client needs them to talk to this server.
	Server AmneziaServerConfig `yaml:"server"`
	// Shared holds values that the server and every client must agree on.
	Shared AmneziaSharedConfig `yaml:"shared"`
	// Client holds values that only go into client configurations.
	Client AmneziaClientConfig `yaml:"client"`
}

type AmneziaServerConfig struct {
	// HeaderProtectionKey encrypts the 32-byte packet header. Generate it with
	// `awg genkey` (or any 32-byte key) and keep it - a new key means every
	// client configuration has to be downloaded again.
	//
	// It is a secret on the server, not from the clients: a client that does
	// not have it cannot read a single packet from this server.
	HeaderProtectionKey string `yaml:"headerProtectionKey"`
}

type AmneziaSharedConfig struct {
	// Padding of the init, response, cookie and transport messages. Header
	// protection needs at least 12 bytes on each, or the cipher would read
	// real header bytes as its nonce.
	S1 uint32 `yaml:"s1"`
	S2 uint32 `yaml:"s2"`
	S3 uint32 `yaml:"s3"`
	S4 uint32 `yaml:"s4"`
	// Uint32 ranges ("123-456" or "1234") at the start of each message type.
	// The four ranges must not overlap.
	H1 string `yaml:"h1"`
	H2 string `yaml:"h2"`
	H3 string `yaml:"h3"`
	H4 string `yaml:"h4"`

	// RandomTrailers pads every packet to a random size below the largest one
	// seen so far. It changes what the receiver has to accept, so it has to be
	// on at both ends - unlike the junk and signature packets, which only the
	// sender needs.
	RandomTrailers bool `yaml:"randomTrailers"`

	// DisableCookies stops the interface from sending cookie replies at all,
	// removing one packet type from the fingerprint. Like the other shared
	// settings, both ends use it the same way.
	DisableCookies bool `yaml:"disableCookies"`

	// ContentPaddingAddition is a random per-packet padding range ("10-20").
	// It replaces the random-trailer amount for transport packets, so
	// RandomTrailers still has to be on for the receiver to accept them.
	ContentPaddingAddition string `yaml:"contentPaddingAddition"`
}

type AmneziaClientConfig struct {
	// Junk packets sent before every handshake: JC of them, each JMin..JMax
	// bytes. Keep JMax below the client MTU, or the packets get fragmented.
	JC   uint32 `yaml:"jc"`
	JMin uint32 `yaml:"jmin"`
	JMax uint32 `yaml:"jmax"`
	// Custom signature packets, sent in order before every handshake.
	I1 string `yaml:"i1"`
	I2 string `yaml:"i2"`
	I3 string `yaml:"i3"`
	I4 string `yaml:"i4"`
	I5 string `yaml:"i5"`
	// The timings of the protocol. They only shape this client's own
	// behaviour, so they may differ between clients.
	RekeyAfterTime       string `yaml:"rekeyAfterTime"`
	RekeyTimeout         string `yaml:"rekeyTimeout"`
	RejectAfterTime      string `yaml:"rejectAfterTime"`
	KeepaliveTimeout     string `yaml:"keepaliveTimeout"`
	MaxHandshakeAttempts string `yaml:"maxHandshakeAttempts"`
}

// IsZero reports whether no parameter is set at all, in which case the server
// runs as a plain WireGuard server.
func (a AmneziaConfig) IsZero() bool {
	return a.Server.HeaderProtectionKey == "" && a.Shared.IsZero() && a.Client.IsZero()
}

func (a AmneziaSharedConfig) IsZero() bool {
	return a.S1 == 0 && a.S2 == 0 && a.S3 == 0 && a.S4 == 0 &&
		a.H1 == "" && a.H2 == "" && a.H3 == "" && a.H4 == "" &&
		!a.RandomTrailers && !a.DisableCookies && a.ContentPaddingAddition == ""
}

func (a AmneziaClientConfig) IsZero() bool {
	return a.JC == 0 && a.JMin == 0 && a.JMax == 0 &&
		a.I1 == "" && a.I2 == "" && a.I3 == "" && a.I4 == "" && a.I5 == "" &&
		a.RekeyAfterTime == "" && a.RekeyTimeout == "" &&
		a.RejectAfterTime == "" && a.KeepaliveTimeout == "" &&
		a.MaxHandshakeAttempts == ""
}

// Validate rejects a profile the device or a client would not accept. mtu is
// the client-facing MTU: junk packets larger than that get fragmented, which
// is exactly what the obfuscation is meant to avoid.
func (a AmneziaConfig) Validate(mtu int) error {
	if a.IsZero() {
		return nil
	}

	// The shared half is what both sides must agree on, and a set header
	// protection key without matching padding is a profile that cannot work -
	// the device would refuse it, or silently fall back to zero padding.
	if a.Server.HeaderProtectionKey != "" {
		for _, padding := range []struct {
			name  string
			value uint32
		}{{"s1", a.Shared.S1}, {"s2", a.Shared.S2}, {"s3", a.Shared.S3}, {"s4", a.Shared.S4}} {
			if padding.value < 12 {
				return fmt.Errorf("%s must be at least 12 when server.headerProtectionKey is set, because the header cipher reads a 12-byte nonce", padding.name)
			}
		}
	}
	if err := validateHeaderRanges(a.Shared); err != nil {
		return err
	}
	if a.Client.JMax != 0 && mtu > 0 && int(a.Client.JMax) >= mtu {
		return fmt.Errorf("client.jmax (%d) must be smaller than the client MTU (%d), or the junk packets are fragmented", a.Client.JMax, mtu)
	}

	// Content padding makes transport packets larger than the message size,
	// and the receiver only accepts that when it pads as well. Getting this
	// wrong looks like a working server and a tunnel that drops every data
	// packet, so it is refused rather than left to the device.
	if a.Shared.ContentPaddingAddition != "" {
		_, high, err := parseUintRange(a.Shared.ContentPaddingAddition)
		if err == nil && high > 0 && !a.Shared.RandomTrailers {
			return errors.New("shared.contentPaddingAddition needs shared.randomTrailers: the receiver only accepts the larger packets when it pads too")
		}
	}

	// Everything else is the same check the device does, so the rules live in
	// one place: key format, padding bounds, range and signature-packet
	// syntax, jmin <= jmax.
	if err := a.clientAndDeviceConfig().Validate(); err != nil {
		return err
	}
	return nil
}

// DeviceConfig is what this server's own interface needs: the shared values and
// the header protection key. Client-only values are not sent to the device -
// they have no meaning there.
func (a AmneziaConfig) DeviceConfig() wgembed.AmneziaConfig {
	return wgembed.AmneziaConfig{
		S1:                     uint32Value(a.Shared.S1),
		S2:                     uint32Value(a.Shared.S2),
		S3:                     uint32Value(a.Shared.S3),
		S4:                     uint32Value(a.Shared.S4),
		H1:                     stringValue(a.Shared.H1),
		H2:                     stringValue(a.Shared.H2),
		H3:                     stringValue(a.Shared.H3),
		H4:                     stringValue(a.Shared.H4),
		RandomTrailers:         a.Shared.RandomTrailers,
		DisableCookies:         a.Shared.DisableCookies,
		ContentPaddingAddition: stringValue(a.Shared.ContentPaddingAddition),
		HeaderProtectionKey:    a.Server.HeaderProtectionKey,
	}
}

// clientAndDeviceConfig is the union of everything the server knows, used to
// validate client-side values with the device's own rules.
func (a AmneziaConfig) clientAndDeviceConfig() wgembed.AmneziaConfig {
	c := a.DeviceConfig()
	c.JC = uint32Value(a.Client.JC)
	c.JMin = uint32Value(a.Client.JMin)
	c.JMax = uint32Value(a.Client.JMax)
	c.I1 = stringValue(a.Client.I1)
	c.I2 = stringValue(a.Client.I2)
	c.I3 = stringValue(a.Client.I3)
	c.I4 = stringValue(a.Client.I4)
	c.I5 = stringValue(a.Client.I5)
	c.RekeyAfterTime = stringValue(a.Client.RekeyAfterTime)
	c.RekeyTimeout = stringValue(a.Client.RekeyTimeout)
	c.RejectAfterTime = stringValue(a.Client.RejectAfterTime)
	c.KeepaliveTimeout = stringValue(a.Client.KeepaliveTimeout)
	c.MaxHandshakeAttempts = stringValue(a.Client.MaxHandshakeAttempts)
	return c
}

func uint32Value(v uint32) *uint32 {
	if v == 0 {
		return nil
	}
	return &v
}

func stringValue(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

// validateHeaderRanges checks the four message-type ranges: each has to parse,
// and they must not overlap, or a packet cannot be identified by its header.
func validateHeaderRanges(shared AmneziaSharedConfig) error {
	type namedRange struct {
		name     string
		low, hig uint32
	}
	ranges := make([]namedRange, 0, 4)
	for _, r := range []struct {
		name  string
		value string
	}{{"h1", shared.H1}, {"h2", shared.H2}, {"h3", shared.H3}, {"h4", shared.H4}} {
		if r.value == "" {
			continue
		}
		low, hig, err := parseUintRange(r.value)
		if err != nil {
			return fmt.Errorf("shared.%s: %w", r.name, err)
		}
		ranges = append(ranges, namedRange{name: r.name, low: low, hig: hig})
	}

	for i := 0; i < len(ranges); i++ {
		for j := i + 1; j < len(ranges); j++ {
			if ranges[i].low <= ranges[j].hig && ranges[j].low <= ranges[i].hig {
				return fmt.Errorf("shared.%s and shared.%s overlap", ranges[i].name, ranges[j].name)
			}
		}
	}
	return nil
}

// parseUintRange accepts exactly what AmneziaWG accepts for a header range:
// "1234" or "123-456", with no surrounding space - a value that is accepted
// here has to be one the device accepts as well.
func parseUintRange(value string) (uint32, uint32, error) {
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return 0, 0, fmt.Errorf("%q is not a number or a range", value)
	}
	low, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("%q is not a number or a range", value)
	}
	if len(parts) == 1 {
		return uint32(low), uint32(low), nil
	}
	high, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("%q is not a number or a range", value)
	}
	if high < low {
		return 0, 0, fmt.Errorf("%q ends before it begins", value)
	}
	return uint32(low), uint32(high), nil
}
