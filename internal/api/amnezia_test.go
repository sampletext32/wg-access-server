package api

import (
	"testing"

	"github.com/freifunkMUC/wg-access-server/internal/config"
)

func TestAmneziaClientConfigIsNilWithoutAProfile(t *testing.T) {
	if got := amneziaClientConfig(config.AmneziaConfig{}); got != nil {
		t.Fatalf("a server without a profile must send none, got %v", got)
	}
}

func TestAmneziaClientConfigCarriesWhatAClientNeeds(t *testing.T) {
	profile := config.AmneziaConfig{
		Server: config.AmneziaServerConfig{HeaderProtectionKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		Shared: config.AmneziaSharedConfig{
			S1: 17, S2: 29, S3: 43, S4: 12,
			H1: "123456-123500", H2: "67543-67550",
			H3: "123123-123200", H4: "32345-32350",
		},
		Client: config.AmneziaClientConfig{
			JC: 4, JMin: 500, JMax: 1000,
			I1:                     "<b 0xf6ab3267fa><c><t>",
			ContentPaddingAddition: "10-20",
			MaxHandshakeAttempts:   "5",
		},
	}

	got := amneziaClientConfig(profile)
	if got == nil {
		t.Fatal("a configured profile must be sent")
	}

	if got.Jc != 4 || got.Jmin != 500 || got.Jmax != 1000 {
		t.Errorf("junk packet settings not carried: %+v", got)
	}
	if got.S1 != 17 || got.S2 != 29 || got.S3 != 43 || got.S4 != 12 {
		t.Errorf("padding not carried: %+v", got)
	}
	if got.H1 != "123456-123500" || got.H2 != "67543-67550" || got.H3 != "123123-123200" || got.H4 != "32345-32350" {
		t.Errorf("headers not carried: %+v", got)
	}
	if got.I1 != "<b 0xf6ab3267fa><c><t>" {
		t.Errorf("signature packet not carried: %q", got.I1)
	}
	if got.ContentPaddingAddition != "10-20" || got.MaxHandshakeAttempts != "5" {
		t.Errorf("padding/timing settings not carried: %+v", got)
	}
}
