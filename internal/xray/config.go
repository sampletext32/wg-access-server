package xray

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/freifunkMUC/wg-access-server/internal/config"
)

// The tags below are Xray's own; they are the wire format, not a choice of
// ours, so they stay in one file where the whole document can be read at once.

type serverConfig struct {
	Log       logConfig     `json:"log"`
	API       apiConfig     `json:"api"`
	Stats     statsConfig   `json:"stats"`
	Policy    policyConfig  `json:"policy"`
	Inbounds  []inbound     `json:"inbounds"`
	Routing   routingConfig `json:"routing"`
	Outbounds []outbound    `json:"outbounds"`
}

type logConfig struct {
	LogLevel string `json:"loglevel"`
}

// apiConfig turns on the management API. Its tag is the target of the routing
// rule below: an inbound carrying that tag is answered by the API rather than
// by the internet, which is how users are added and counters read without
// restarting the process.
type apiConfig struct {
	Tag      string   `json:"tag"`
	Services []string `json:"services"`
}

type statsConfig struct{}

// policyConfig is what makes the counters per user rather than per inbound. A
// user without a level is at level 0, which is the level switched on here.
type policyConfig struct {
	Levels map[string]levelPolicy `json:"levels"`
}

type levelPolicy struct {
	StatsUserUplink   bool `json:"statsUserUplink"`
	StatsUserDownlink bool `json:"statsUserDownlink"`
}

type inbound struct {
	Tag            string          `json:"tag"`
	Listen         string          `json:"listen,omitempty"`
	Port           int             `json:"port"`
	Protocol       string          `json:"protocol"`
	Settings       inboundSettings `json:"settings"`
	StreamSettings *streamSettings `json:"streamSettings,omitempty"`
}

type inboundSettings struct {
	// Clients, for the VLESS inbound.
	Clients []client `json:"clients,omitempty"`
	// Decryption is required by the VLESS inbound and is always "none": VLESS
	// itself does not encrypt, the transport does.
	Decryption string `json:"decryption,omitempty"`
	// Address, for the API inbound: a dokodemo-door listener that the routing
	// rule sends to the API service.
	Address string `json:"address,omitempty"`
}

// client is one device on the VLESS inbound. The email is the counter key, and
// this server sets it to the same value as the id, so a counter can be mapped
// back to a device without a second table.
type client struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Flow  string `json:"flow,omitempty"`
}

type streamSettings struct {
	Network         string           `json:"network"`
	Security        string           `json:"security"`
	RealitySettings *realitySettings `json:"realitySettings,omitempty"`
}

// realitySettings is the disguise: the server answers a client that proves it
// knows the key, and hands everybody else to Dest, which is the cover site.
type realitySettings struct {
	Show        bool     `json:"show"`
	Dest        string   `json:"dest"`
	Xver        int      `json:"xver"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIDs    []string `json:"shortIds"`
}

type routingConfig struct {
	Rules []routingRule `json:"rules"`
}

type routingRule struct {
	Type        string   `json:"type"`
	InboundTag  []string `json:"inboundTag"`
	OutboundTag string   `json:"outboundTag"`
}

type outbound struct {
	Protocol string            `json:"protocol"`
	Settings *outboundSettings `json:"settings,omitempty"`
}

// outboundSettings carries the rules the freedom outbound applies just before
// it dials. They exist because of a default Xray has since v26: traffic from a
// VLESS inbound may not reach private or reserved addresses unless a rule
// allows it. That is the right default - a VPN user should not be able to reach
// the cluster the server runs in - but the DNS resolvers this server hands to
// its clients are private addresses, so exactly those have to be allowed.
type outboundSettings struct {
	FinalRules []finalRule `json:"finalRules,omitempty"`
}

// finalRule allows or blocks a target. Only the fields that are set take part
// in the match, and all of them have to match.
type finalRule struct {
	Action  string   `json:"action"`
	Network string   `json:"network,omitempty"`
	Port    string   `json:"port,omitempty"`
	IP      []string `json:"ip,omitempty"`
}

// render builds the whole document from the configured parameters and the users
// the process is supposed to have.
func render(cfg config.VLESSConfig, ids []string) serverConfig {
	sort.Strings(ids)

	clients := make([]client, 0, len(ids))
	for _, id := range ids {
		clients = append(clients, client{ID: id, Email: id, Flow: cfg.Flow})
	}

	return serverConfig{
		Log:   logConfig{LogLevel: cfg.LogLevel},
		API:   apiConfig{Tag: apiTag, Services: []string{"HandlerService", "StatsService"}},
		Stats: statsConfig{},
		Policy: policyConfig{Levels: map[string]levelPolicy{
			"0": {StatsUserUplink: true, StatsUserDownlink: true},
		}},
		Inbounds: []inbound{
			{
				Tag:      vlessTag,
				Listen:   "0.0.0.0",
				Port:     cfg.ListenPort,
				Protocol: "vless",
				Settings: inboundSettings{Clients: clients, Decryption: "none"},
				StreamSettings: &streamSettings{
					Network:  "tcp",
					Security: "reality",
					RealitySettings: &realitySettings{
						Dest:        cfg.Dest(),
						ServerNames: []string{cfg.ServerName()},
						PrivateKey:  cfg.RealityPrivateKey,
						ShortIDs:    []string{cfg.ShortID},
					},
				},
			},
			{
				Tag:      apiTag,
				Listen:   "127.0.0.1",
				Port:     cfg.APIPort,
				Protocol: "dokodemo-door",
				Settings: inboundSettings{Address: "127.0.0.1"},
			},
		},
		Routing:   routingConfig{Rules: []routingRule{{Type: "field", InboundTag: []string{apiTag}, OutboundTag: apiTag}}},
		Outbounds: []outbound{freedomOutbound()},
	}
}

// Tags are fixed: the API call names the inbound it adds a user to, and the
// routing rule names the API itself.
const (
	vlessTag = "vless-in"
	apiTag   = "api"
)

// writeConfig renders the document and puts it in place atomically: Xray reads
// this file when it starts, and a half-written file would make it exit.
func writeConfig(path string, cfg config.VLESSConfig, ids []string) error {
	document, err := json.MarshalIndent(render(cfg, ids), "", "  ")
	if err != nil {
		return fmt.Errorf("failed to render the Xray configuration: %w", err)
	}
	// 0600: the file carries the REALITY private key.
	temporary := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(temporary, document, 0o600); err != nil {
		return fmt.Errorf("failed to write the Xray configuration: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("failed to move the Xray configuration into place: %w", err)
	}
	return nil
}

// userFragment is what `xray api adu` expects: a configuration fragment whose
// inbounds carry the users to add. The API command reads files, not arguments,
// and it wants a full inbound - tag, port, protocol and settings - even though
// only the users are new. The port is not used to find the inbound, but the
// parser refuses the fragment without one.
func userFragment(cfg config.VLESSConfig, id string) ([]byte, error) {
	fragment := serverConfig{Inbounds: []inbound{{
		Tag:      vlessTag,
		Port:     cfg.ListenPort,
		Protocol: "vless",
		Settings: inboundSettings{
			Clients:    []client{{ID: id, Email: id, Flow: cfg.Flow}},
			Decryption: "none",
		},
	}}}
	document, err := json.Marshal(fragment)
	if err != nil {
		return nil, fmt.Errorf("failed to render the user fragment: %w", err)
	}
	return document, nil
}

// freedomOutbound is the outbound every proxied connection uses.
//
// The unconditional allow rule is there because of a default Xray has since
// v26: traffic from a VLESS inbound may not reach private or reserved addresses
// unless a rule allows it. That default protects a server whose proxy is
// exposed to strangers; it is wrong here. This server's WireGuard dataplane
// forwards whatever the configuration allows - 0.0.0.0/0 means every address,
// the cluster's and the tunnel's own included - and a second protocol that
// quietly refuses a part of the same address space behaves unlike the first for
// no reason a user could discover. The rule has no conditions, which is Xray's
// documented way of switching the policy off.
func freedomOutbound() outbound {
	return outbound{
		Protocol: "freedom",
		Settings: &outboundSettings{FinalRules: []finalRule{{Action: "allow"}}},
	}
}