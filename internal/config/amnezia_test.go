package config

import (
	"strings"
	"testing"
)

// testHeaderKey is a syntactically valid 32-byte key. It is deliberately of low
// entropy: a made-up key that looks real trips secret scanners.
const testHeaderKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func validProfile() AmneziaConfig {
	return AmneziaConfig{
		Server: AmneziaServerConfig{HeaderProtectionKey: testHeaderKey},
		Shared: AmneziaSharedConfig{
			S1: 17, S2: 29, S3: 43, S4: 12,
			H1: "123456-123500", H2: "67543-67550",
			H3: "123123-123200", H4: "32345-32350",
		},
		Client: AmneziaClientConfig{
			JC: 4, JMin: 500, JMax: 1000,
			I1: "<b 0xf6ab3267fa><c><t>",
		},
	}
}

func TestAmneziaConfigIsZero(t *testing.T) {
	if !(AmneziaConfig{}).IsZero() {
		t.Fatal("an empty profile must report itself as zero")
	}
	if (AmneziaConfig{Shared: AmneziaSharedConfig{S1: 8}}).IsZero() {
		t.Fatal("one set value is enough for a profile")
	}
	if (AmneziaConfig{Server: AmneziaServerConfig{HeaderProtectionKey: testHeaderKey}}).IsZero() {
		t.Fatal("a header protection key alone is a profile")
	}
}

func TestAmneziaConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		profile AmneziaConfig
		mtu     int
		wantErr string
	}{
		{
			name:    "no profile is plain WireGuard",
			profile: AmneziaConfig{},
			mtu:     1420,
		},
		{
			name:    "a complete profile",
			profile: validProfile(),
			mtu:     1360,
		},
		{
			name: "jmin above jmax",
			profile: func() AmneziaConfig {
				p := validProfile()
				p.Client.JMin, p.Client.JMax = 2000, 1000
				return p
			}(),
			mtu:     1360,
			wantErr: "jmin must not be larger than jmax",
		},
		{
			name: "header protection without padding",
			profile: func() AmneziaConfig {
				p := validProfile()
				p.Shared.S1, p.Shared.S2, p.Shared.S3, p.Shared.S4 = 0, 0, 0, 0
				return p
			}(),
			mtu:     1360,
			wantErr: "must be at least 12",
		},
		{
			name: "header protection with too little padding",
			profile: func() AmneziaConfig {
				p := validProfile()
				p.Shared.S4 = 8
				return p
			}(),
			mtu:     1360,
			wantErr: "s4 must be at least 12",
		},
		{
			name: "no header protection, no padding needed",
			profile: func() AmneziaConfig {
				p := validProfile()
				p.Server.HeaderProtectionKey = ""
				p.Shared.S1, p.Shared.S2, p.Shared.S3, p.Shared.S4 = 0, 0, 0, 0
				return p
			}(),
			mtu: 1360,
		},
		{
			name: "a header range that is not a range",
			profile: func() AmneziaConfig {
				p := validProfile()
				p.Shared.H2 = "not-a-range"
				return p
			}(),
			mtu:     1360,
			wantErr: "shared.h2",
		},
		{
			name: "overlapping header ranges",
			profile: func() AmneziaConfig {
				p := validProfile()
				p.Shared.H1 = "100-200"
				p.Shared.H2 = "150-250"
				return p
			}(),
			mtu:     1360,
			wantErr: "overlap",
		},
		{
			name: "junk packets that would fragment",
			profile: func() AmneziaConfig {
				p := validProfile()
				p.Client.JMax = 1400
				return p
			}(),
			mtu:     1400,
			wantErr: "must be smaller than the client MTU",
		},
		{
			name: "a header protection key that is not a key",
			profile: func() AmneziaConfig {
				p := validProfile()
				p.Server.HeaderProtectionKey = "not-a-key"
				return p
			}(),
			mtu:     1360,
			wantErr: "header protection key is invalid",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.profile.Validate(test.mtu)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q", test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error %q does not contain %q", err, test.wantErr)
			}
		})
	}
}

func TestAmneziaConfigDeviceConfig(t *testing.T) {
	device := validProfile().DeviceConfig()

	if device.HeaderProtectionKey != testHeaderKey {
		t.Error("the header protection key belongs on the device")
	}
	if device.S1 == nil || *device.S1 != 17 {
		t.Error("s1 belongs on the device")
	}
	if device.H1 == nil || *device.H1 != "123456-123500" {
		t.Error("h1 belongs on the device")
	}
	// Client-only values have no meaning on the server's interface.
	if device.JC != nil || device.JMin != nil || device.JMax != nil {
		t.Error("junk packet settings must not reach the device")
	}
	if device.I1 != nil {
		t.Error("signature packets must not reach the device")
	}
}

func TestAmneziaConfigDeviceConfigOmitsUnsetValues(t *testing.T) {
	device := (AmneziaConfig{Shared: AmneziaSharedConfig{S1: 12}}).DeviceConfig()

	if device.S1 == nil || *device.S1 != 12 {
		t.Error("s1 must be set")
	}
	if device.S2 != nil || device.S3 != nil || device.S4 != nil {
		t.Error("unset padding must stay unset, not become zero")
	}
	if device.H1 != nil {
		t.Error("unset headers must stay unset")
	}
}
