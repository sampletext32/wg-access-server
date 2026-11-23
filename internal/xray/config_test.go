package xray

import (
	"encoding/json"
	"testing"

	"github.com/freifunkMUC/wg-access-server/internal/config"
)

func testConfig() config.VLESSConfig {
	return config.VLESSConfig{
		Enabled:           true,
		ListenPort:        10443,
		APIPort:           10085,
		PublicHost:        "vless.example.test",
		PublicPort:        443,
		CoverHost:         "www.example.com",
		RealityPrivateKey: "IF9gjcvJIRxIQrC-durMAi6nlcrgzjd2nhNUBkumDkU",
		ShortID:           "106349f5e72cdab8",
		Flow:              config.DefaultVLESSFlow,
		Fingerprint:       config.DefaultVLESSFingerprint,
		ALPN:              []string{"h2"},
	}
}

// The rendered document is what Xray reads at startup, so its shape is the
// contract with the binary: one VLESS inbound carrying every device, an API
// inbound on loopback, and the routing rule without which the API inbound is
// just another dead listener.
func TestRenderCarriesEveryDeviceAndTheAPI(t *testing.T) {
	cfg := testConfig()
	document := render(cfg, []string{"bbb", "aaa"})

	if len(document.Inbounds) != 2 {
		t.Fatalf("inbounds = %d, want the VLESS one and the API one", len(document.Inbounds))
	}
	vless := document.Inbounds[0]
	if vless.Tag != vlessTag || vless.Protocol != "vless" || vless.Port != cfg.ListenPort {
		t.Errorf("vless inbound = %+v", vless)
	}
	if len(vless.Settings.Clients) != 2 {
		t.Fatalf("clients = %d, want one per device", len(vless.Settings.Clients))
	}
	// Sorted, so that a restart with the same devices writes the same file.
	if vless.Settings.Clients[0].ID != "aaa" || vless.Settings.Clients[1].ID != "bbb" {
		t.Errorf("clients are not in a stable order: %+v", vless.Settings.Clients)
	}
	// The email is the counter key; the server maps a counter back to a
	// device through it, so it has to be the id.
	if vless.Settings.Clients[0].Email != "aaa" || vless.Settings.Clients[0].Flow != cfg.Flow {
		t.Errorf("client = %+v, want the id as email and the configured flow", vless.Settings.Clients[0])
	}
	if vless.Settings.Decryption != "none" {
		t.Errorf("decryption = %q, want none", vless.Settings.Decryption)
	}

	reality := vless.StreamSettings.RealitySettings
	if vless.StreamSettings.Security != "reality" || reality == nil {
		t.Fatalf("the inbound is not REALITY: %+v", vless.StreamSettings)
	}
	if reality.Dest != "www.example.com:443" {
		t.Errorf("dest = %q", reality.Dest)
	}
	if len(reality.ServerNames) != 1 || reality.ServerNames[0] != cfg.CoverHost {
		t.Errorf("serverNames = %v", reality.ServerNames)
	}
	if reality.PrivateKey != cfg.RealityPrivateKey {
		t.Error("the inbound does not carry the configured private key")
	}
	if len(reality.ShortIDs) != 1 || reality.ShortIDs[0] != cfg.ShortID {
		t.Errorf("shortIds = %v", reality.ShortIDs)
	}

	api := document.Inbounds[1]
	if api.Tag != apiTag || api.Listen != "127.0.0.1" || api.Port != cfg.APIPort {
		t.Errorf("api inbound = %+v", api)
	}
	if document.API.Tag != apiTag {
		t.Errorf("api tag = %q, want it to name the inbound", document.API.Tag)
	}
	if len(document.Routing.Rules) != 1 {
		t.Fatalf("routing rules = %d, want the one that sends the API inbound to the API", len(document.Routing.Rules))
	}
	rule := document.Routing.Rules[0]
	if len(rule.InboundTag) != 1 || rule.InboundTag[0] != apiTag || rule.OutboundTag != apiTag {
		t.Errorf("routing rule = %+v", rule)
	}

	// Per-user counters are off by default in Xray; without this the stats
	// call answers with nothing and every device looks idle.
	if !document.Policy.Levels["0"].StatsUserUplink || !document.Policy.Levels["0"].StatsUserDownlink {
		t.Errorf("per-user counters are not enabled: %+v", document.Policy)
	}
}

// `xray api adu` reads a configuration fragment from a file and refuses one
// without a port, an inbound tag or the protocol - all three were found by
// trying, in research/spikes/vless-m0/results.md. This test is that finding,
// frozen.
func TestUserFragmentIsWhatTheAPIAccepts(t *testing.T) {
	cfg := testConfig()
	document, err := userFragment(cfg, "device-uuid")
	if err != nil {
		t.Fatal(err)
	}

	var fragment serverConfig
	if err := json.Unmarshal(document, &fragment); err != nil {
		t.Fatalf("the fragment is not JSON: %v", err)
	}
	if len(fragment.Inbounds) != 1 {
		t.Fatalf("inbounds = %d, want one", len(fragment.Inbounds))
	}
	inbound := fragment.Inbounds[0]
	if inbound.Tag != vlessTag {
		t.Errorf("tag = %q, want %q", inbound.Tag, vlessTag)
	}
	if inbound.Port != cfg.ListenPort {
		t.Errorf("port = %d, want %d", inbound.Port, cfg.ListenPort)
	}
	if inbound.Protocol != "vless" {
		t.Errorf("protocol = %q", inbound.Protocol)
	}
	if len(inbound.Settings.Clients) != 1 || inbound.Settings.Clients[0].ID != "device-uuid" {
		t.Errorf("clients = %+v", inbound.Settings.Clients)
	}
	if inbound.Settings.Decryption != "none" {
		t.Errorf("decryption = %q", inbound.Settings.Decryption)
	}
}

// The counter names are Xray's, and a name this server does not understand must
// be skipped rather than counted under a wrong device.
func TestParseStatName(t *testing.T) {
	id, direction, ok := parseStatName("user>>>abc>>>traffic>>>uplink")
	if !ok || id != "abc" || direction != "uplink" {
		t.Fatalf("parsed %q as %q/%q (ok=%v)", "user>>>abc>>>traffic>>>uplink", id, direction, ok)
	}
	for _, name := range []string{"", "user>>>abc", "inbound>>>abc>>>traffic>>>uplink", "user>>>abc>>>traffic"} {
		if _, _, ok := parseStatName(name); ok {
			t.Errorf("%q was accepted", name)
		}
	}
}

// Xray blocks private targets from a VLESS inbound since v26 unless a rule
// allows them. This server does not: the WireGuard side forwards everything the
// configuration allows, and the second protocol has to behave the same. The
// rule is therefore unconditional - no network, port or address - which is how
// Xray documents switching the policy off.
func TestFreedomForwardsEverything(t *testing.T) {
	outbound := freedomOutbound()
	if outbound.Protocol != "freedom" {
		t.Fatalf("protocol = %q", outbound.Protocol)
	}
	if outbound.Settings == nil || len(outbound.Settings.FinalRules) != 1 {
		t.Fatalf("expected exactly one rule: %+v", outbound.Settings)
	}
	rule := outbound.Settings.FinalRules[0]
	if rule.Action != "allow" {
		t.Errorf("action = %q, want allow", rule.Action)
	}
	if rule.Network != "" || rule.Port != "" || len(rule.IP) != 0 {
		t.Errorf("rule = %+v, want no conditions at all: a restricted allow rule would still block part of the address space", rule)
	}
}