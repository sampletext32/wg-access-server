package config

import (
	"strings"
	"testing"
)

// The pair is one `xray x25519` printed while testing REALITY in a pod; it is
// synthetic and belongs to no server. What it pins down is that the public half
// is derived from the private one rather than stored, so the two can never
// disagree and a client is never handed a key the server does not use.
func TestVLESSDerivesThePublicKey(t *testing.T) {
	cfg := VLESSConfig{
		Enabled:           true,
		PublicHost:        "vless.example.test",
		CoverHost:         "www.example.com",
		RealityPrivateKey: "IF9gjcvJIRxIQrC-durMAi6nlcrgzjd2nhNUBkumDkU",
		ShortID:           "106349f5e72cdab8",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the profile was refused: %v", err)
	}
	const want = "TI2jPsG2cMa5BFmBMnq8PxHSvb3mXDoOLumcRixHs2A"
	if got := cfg.PublicKey(); got != want {
		t.Errorf("public key = %q, want %q", got, want)
	}
	// The details that go into every client configuration, and into the
	// routing rule in front of the server.
	if cfg.Dest() != "www.example.com:443" {
		t.Errorf("dest = %q, want the cover site on 443", cfg.Dest())
	}
	if cfg.ServerName() != "www.example.com" {
		t.Errorf("server name = %q, want the cover host", cfg.ServerName())
	}
	if cfg.Flow != DefaultVLESSFlow {
		t.Errorf("flow = %q, want the default %q", cfg.Flow, DefaultVLESSFlow)
	}
	if cfg.ListenPort != DefaultVLESSListenPort || cfg.APIPort != DefaultVLESSAPIPort {
		t.Errorf("ports = %d/%d, want the defaults %d/%d",
			cfg.ListenPort, cfg.APIPort, DefaultVLESSListenPort, DefaultVLESSAPIPort)
	}
}

// A profile that can only produce configurations that do not connect has to be
// refused at startup, where it is a configuration mistake, rather than at
// connect time, where it looks like a network problem.
func TestVLESSValidationRefusesBrokenProfiles(t *testing.T) {
	valid := VLESSConfig{
		Enabled:           true,
		PublicHost:        "vless.example.test",
		CoverHost:         "www.example.com",
		RealityPrivateKey: "IF9gjcvJIRxIQrC-durMAi6nlcrgzjd2nhNUBkumDkU",
		ShortID:           "106349f5e72cdab8",
	}

	cases := map[string]func(*VLESSConfig){
		"no cover host":          func(c *VLESSConfig) { c.CoverHost = "" },
		"cover host with scheme": func(c *VLESSConfig) { c.CoverHost = "https://www.example.com" },
		"cover host with port":   func(c *VLESSConfig) { c.CoverHost = "www.example.com:443" },
		"cover host is our own":  func(c *VLESSConfig) { c.CoverHost = c.PublicHost },
		"empty key":              func(c *VLESSConfig) { c.RealityPrivateKey = "" },
		"key is not base64":      func(c *VLESSConfig) { c.RealityPrivateKey = "AAAA AAAA" },
		"key is too short":       func(c *VLESSConfig) { c.RealityPrivateKey = "AAAA" },
		"short id is not hex":    func(c *VLESSConfig) { c.ShortID = "zzzzzzzz" },
		"short id is odd":        func(c *VLESSConfig) { c.ShortID = "abc" },
		"short id is too long":   func(c *VLESSConfig) { c.ShortID = strings.Repeat("ab", 9) },
		"unknown flow":           func(c *VLESSConfig) { c.Flow = "xtls-rprx-something" },
		"ports collide":          func(c *VLESSConfig) { c.ListenPort, c.APIPort = 9999, 9999 },
		// Nothing clients could dial: a configuration with no address is one
		// nobody can import, so it is refused at startup rather than exported.
		"no address to dial": func(c *VLESSConfig) { c.PublicHost, c.PublicIP = "", "" },
	}

	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			breakIt(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("the profile was accepted")
			}
		})
	}

	// An address that is not an address is refused: it would go into every
	// client configuration as the thing to dial.
	withBadIP := valid
	withBadIP.PublicIP = "vless.example.test"
	if err := withBadIP.Validate(); err == nil {
		t.Fatal("a host name in vless.publicIP was accepted")
	}

	// And the one that has to keep working.
	cfg := valid
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the valid profile was refused: %v", err)
	}
	// What clients dial is the address when there is one, the name otherwise.
	if got := cfg.DialAddress(); got != valid.PublicHost {
		t.Errorf("dial address = %q, want the host without a publicIP", got)
	}
	cfg.PublicIP = "203.0.113.10"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the profile with an address was refused: %v", err)
	}
	if got := cfg.DialAddress(); got != "203.0.113.10" {
		t.Errorf("dial address = %q, want the configured address", got)
	}
}

// A server without VLESS must not be forced to configure any of it.
func TestVLESSDisabledNeedsNothing(t *testing.T) {
	var cfg VLESSConfig
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a disabled section was validated anyway: %v", err)
	}
	if cfg.PublicKey() != "" {
		t.Error("a disabled section derived a key")
	}
}
