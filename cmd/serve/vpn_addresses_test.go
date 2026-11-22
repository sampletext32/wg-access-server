package serve

import (
	"reflect"
	"testing"

	"github.com/freifunkMUC/wg-access-server/internal/config"
)

// The client configuration has to carry the routes the operator configured and
// nothing else. A separate route for the server's own address is not harmless:
// clients read every route beyond the default ones as "split tunneling is
// decided by the server", and the Android app switches the user's own split
// tunneling off the moment it sees one (`Wireguard.kt`), so a redundant "/32"
// next to 0.0.0.0/0 takes the feature away from every phone.
func TestVPNAddressesAddsTheProxyRouteOnlyWhenNeeded(t *testing.T) {
	tests := []struct {
		name         string
		cidr         string
		allowed      []string
		wantAllowed  []string
		wantPrefixes []string
	}{
		{
			name:         "the default route already covers the server address",
			cidr:         "10.13.0.0/24",
			allowed:      []string{"0.0.0.0/0", "::/0"},
			wantAllowed:  []string{"0.0.0.0/0", "::/0"},
			wantPrefixes: []string{"10.13.0.1/24"},
		},
		{
			name:         "a narrower route leaves the proxy unreachable",
			cidr:         "10.13.0.0/24",
			allowed:      []string{"192.168.0.0/16"},
			wantAllowed:  []string{"192.168.0.0/16", "10.13.0.1/32"},
			wantPrefixes: []string{"10.13.0.1/24"},
		},
		{
			name:         "the address written out on its own is enough",
			cidr:         "10.13.0.0/24",
			allowed:      []string{"0.0.0.0/0", "10.13.0.1"},
			wantAllowed:  []string{"0.0.0.0/0", "10.13.0.1"},
			wantPrefixes: []string{"10.13.0.1/24"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conf := &config.AppConfig{}
			conf.VPN.CIDR = test.cidr
			conf.VPN.AllowedIPs = append([]string(nil), test.allowed...)

			addressing := vpnAddresses(conf)

			if !reflect.DeepEqual(conf.VPN.AllowedIPs, test.wantAllowed) {
				t.Fatalf("allowed IPs = %v, want %v", conf.VPN.AllowedIPs, test.wantAllowed)
			}
			if !reflect.DeepEqual(addressing.prefixes, test.wantPrefixes) {
				t.Fatalf("interface prefixes = %v, want %v", addressing.prefixes, test.wantPrefixes)
			}
		})
	}
}
