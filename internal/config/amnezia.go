package config

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sampletext32/amneziawg-embed/pkg/wgembed"
)

// AmneziaConfig is the AmneziaWG profile of this server. Unlike WireGuard, its
// obfuscation parameters must agree between the server and every client, so
// the same block feeds both: the server's interface gets the shared values and
// the header protection key, and client configuration files get the shared
// values plus the client-only ones.
//
// An empty block means the server speaks plain WireGuard. That is what a
// WireGuard server does, and it is also the safe state for a development
// instance, but it is detectable - the server says so at startup.
type AmneziaConfig struct {
	// Server holds values that must never leave the server.
	Server AmneziaServerConfig `yaml:"server"`
	// Shared holds values that the server and every client must agree on.
	Shared AmneziaSharedConfig `yaml:"shared"`
	// Client holds values that only go into client configurations.
	Client AmneziaClientConfig `yaml:"client"`
}

type AmneziaServerConfig struct {
	// HeaderProtectionKey encrypts the packet headers. Generate it with
	// `awg genkey` (or any 32-byte key) and keep it - a new key means every
	// enrolled device has to be enrolled again.
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
	// Extra padding, and the timings of the protocol.
	ContentPaddingAddition string `yaml:"contentPaddingAddition"`
	RekeyAfterTime         string `yaml:"rekeyAfterTime"`
	RekeyTimeout           string `yaml:"rekeyTimeout"`
	RejectAfterTime        string `yaml:"rejectAfterTime"`
	KeepaliveTimeout       string `yaml:"keepaliveTimeout"`
	MaxHandshakeAttempts   string `yaml:"maxHandshakeAttempts"`
}

// IsZero reports whether no parameter is set at all, in which case the server
// runs as a plain WireGuard server.
func (a AmneziaConfig) IsZero() bool {
	return a.Server.HeaderProtectionKey == "" && a.Shared.IsZero() && a.Client.IsZero()
}

func (a AmneziaSharedConfig) IsZero() bool {
	return a.S1 == 0 && a.S2 == 0 && a.S3 == 0 && a.S4 == 0 &&
		a.H1 == "" && a.H2 == "" && a.H3 == "" && a.H4 == ""
}

func (a AmneziaClientConfig) IsZero() bool {
	return a.JC == 0 && a.JMin == 0 && a.JMax == 0 &&
		a.I1 == "" && a.I2 == "" && a.I3 == "" && a.I4 == "" && a.I5 == "" &&
		a.ContentPaddingAddition == "" &&
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
	// the device would silently fall back to zero padding.
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

	// Everything else is the same check the device does, so the rules live in
	// one place: key format, jmin <= jmax, non-empty range strings.
	if err := a.clientAndDeviceConfig().Validate(); err != nil {
		return err
	}
	return nil
}

// DeviceConfig is what this server's own interface needs: the shared values
// and the header protection key. Client-only values are not sent to the
// device - they have no meaning there.
func (a AmneziaConfig) DeviceConfig() wgembed.AmneziaConfig {
	return wgembed.AmneziaConfig{
		S1:                  uint32Value(a.Shared.S1),
		S2:                  uint32Value(a.Shared.S2),
		S3:                  uint32Value(a.Shared.S3),
		S4:                  uint32Value(a.Shared.S4),
		H1:                  stringValue(a.Shared.H1),
		H2:                  stringValue(a.Shared.H2),
		H3:                  stringValue(a.Shared.H3),
		H4:                  stringValue(a.Shared.H4),
		HeaderProtectionKey: a.Server.HeaderProtectionKey,
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
	c.ContentPaddingAddition = stringValue(a.Client.ContentPaddingAddition)
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

// parseUintRange accepts what AmneziaWG accepts for a header range: "1234" or
// "123-456".
func parseUintRange(value string) (uint32, uint32, error) {
	lowText, highText, isRange := strings.Cut(strings.TrimSpace(value), "-")
	low, err := strconv.ParseUint(strings.TrimSpace(lowText), 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("%q is not a number or a range", value)
	}
	if !isRange {
		return uint32(low), uint32(low), nil
	}
	high, err := strconv.ParseUint(strings.TrimSpace(highText), 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("%q is not a number or a range", value)
	}
	if high < low {
		return 0, 0, fmt.Errorf("%q ends before it begins", value)
	}
	return uint32(low), uint32(high), nil
}
