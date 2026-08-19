package config

import (
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestAmneziaConfigValidateAndServerConversion(t *testing.T) {
	c := AmneziaConfig{
		Shared: AmneziaSharedConfig{S1: 8, S2: 8, S3: 8, S4: 8, H1: "100-200"},
		Server: AmneziaServerConfig{HeaderProtectionKey: (wgtypes.Key{}).String()},
		Client: AmneziaClientConfig{JC: 3, JMin: 10, JMax: 20, I1: "<b 0x1>"},
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	a := c.ServerDeviceConfig()
	if a.S1 == nil || *a.S1 != 8 || a.H1 == nil || *a.H1 != "100-200" {
		t.Fatalf("shared values were not converted: %#v", a)
	}
	if a.JC != nil || a.I1 != nil {
		t.Fatalf("client-only values were applied to server: %#v", a)
	}
}

func TestAmneziaConfigValidationFailures(t *testing.T) {
	tests := []AmneziaConfig{
		{Client: AmneziaClientConfig{JMin: 20, JMax: 10}},
		{Shared: AmneziaSharedConfig{H1: "200-300", H2: "300-400"}},
		{Shared: AmneziaSharedConfig{H1: "not-a-range"}},
		{Server: AmneziaServerConfig{HeaderProtectionKey: "not-a-key"}},
	}
	for i, tc := range tests {
		if err := tc.Validate(); err == nil {
			t.Errorf("case %d unexpectedly passed validation", i)
		}
	}
}
