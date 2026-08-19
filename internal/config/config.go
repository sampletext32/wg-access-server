package config

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/freifunkMUC/wg-access-server/internal/amnezia"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authconfig"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	Day  time.Duration = 24 * time.Hour
	Year               = 365 * Day
)

type AppConfig struct {
	// Set the log level.
	// Defaults to "info" (fatal, error, warn, info, debug, trace)
	LogLevel string `yaml:"loglevel"`
	// Set the superadmin username
	// Defaults to "admin"
	AdminUsername string `yaml:"adminUsername"`
	// Set the superadmin password (required)
	AdminPassword string `yaml:"adminPassword"`
	// Port sets the port that the web UI will listen on.
	// Defaults to 8000
	Port int `yaml:"port"`
	// HTTP listen host
	// Defaults to "" (all hosts)
	HttpHost string `yaml:"httpHost"`
	// ExternalHost is the address that clients
	// use to connect to the WireGuard interface
	// By default, this will be empty and the web ui
	// will use the current page's origin.
	ExternalHost string `yaml:"externalHost"`
	// The storage backend where device configuration will
	// be persisted.
	// Supports memory:// postgresql:// mysql:// sqlite3://
	// Defaults to memory://
	Storage string `yaml:"storage"`
	// Maximum age and idle time for SQL connections. Short values help pools
	// move to the new Patroni primary after a failover.
	StorageConnMaxLifetime time.Duration `yaml:"storageConnMaxLifetime"`
	StorageConnMaxIdleTime time.Duration `yaml:"storageConnMaxIdleTime"`
	// EnableMetadata allows you to turn on collection of device
	// metadata including last handshake time & rx/tx bytes
	EnableMetadata bool `yaml:"enableMetadata"`
	// EnableDeviceMetrics controls whether device-level Prometheus metrics
	// are exposed on /metrics. Requires EnableMetadata to be effective.
	EnableDeviceMetrics bool `yaml:"enableDeviceMetrics"`
	// EnableInactiveDeviceDeletion allows you to delete inactive devices
	// automatically after a time duration defined by InactiveDeviceGracePeriod
	EnableInactiveDeviceDeletion bool `yaml:"enableInactiveDeviceDeletion"`
	// InactiveDeviceGracePeriod sets the duration after which inactive
	// devices are automatically deleted
	// Defaults to 1 year
	InactiveDeviceGracePeriod time.Duration `yaml:"inactiveDeviceGracePeriod"`
	// The name of the WireGuard configuration file that can
	// be downloaded through the web UI after adding a device.
	// Do not include the '.conf' extension
	// Defaults to 'WireGuard' (resulting full name 'WireGuard.conf')
	Filename string `yaml:"filename"`
	// Configure WireGuard related settings
	WireGuard struct {
		// Set this to false to disable the embedded WireGuard
		// server. This is useful for development environments
		// on mac and windows where we don't currently support
		// the OS's network stack.
		Enabled bool `yaml:"enabled"`
		// The network interface name of the WireGuard
		// network device.
		// Defaults to awg0
		Interface string `yaml:"interface"`
		// The WireGuard PrivateKey
		// If this value is lost then any existing
		// clients (WireGuard peers) will no longer
		// be able to connect.
		// Clients will either have to manually update
		// their connection configuration or setup
		// their VPN again using the web ui (easier for most people)
		PrivateKey string `yaml:"privateKey"`
		// The WireGuard ListenPort
		// Defaults to 51820
		Port int `yaml:"port"`
		// The maximum transmission unit (MTU) used on the server-side.
		// Empty by default.
		MTU int `yaml:"mtu"`
		// Path to the supervised amneziawg-go child binary.
		ChildPath string `yaml:"childPath"`
	} `yaml:"wireguard"`
	Amnezia AmneziaConfig `yaml:"amnezia"`
	// Configure VPN related settings (networking)
	VPN struct {
		// The "AllowedIPs" for VPN clients.
		// This value will be included in client config
		// files and in server-side iptable rules
		// to enforce network access.
		// defaults to ["0.0.0.0/0", "::/0"]
		AllowedIPs []string `yaml:"allowedIPs"`
		// CIDR configures a network address space
		// that client (WireGuard peers) will be allocated
		// an IP address from
		// defaults to 10.44.0.0/24
		CIDR string `yaml:"cidr"`
		// CIDRv6 configures an IPv6 network address space
		// that client (WireGuard peers) will be allocated
		// an IP address from
		// defaults to fd48:4c4:7aa9::/64
		CIDRv6 string `yaml:"cidrv6"`
		// GatewayInterface will be used in iptable forwarding
		// rules that send VPN traffic from clients to this interface
		// Most use-cases will want this interface to have access
		// to the outside internet
		GatewayInterface string `yaml:"gatewayInterface"`
		// NAT44 configures whether IPv4 traffic leaving
		// through the GatewayInterface should be masqueraded
		// defaults to true
		NAT44 bool `yaml:"nat44"`
		// NAT66 configures whether IPv6 traffic leaving
		// through the GatewayInterface should be
		// masqueraded like IPv4 traffic
		// defaults to true
		NAT66 bool `yaml:"nat66"`
		// ClientIsolation configures whether traffic between client devices will be blocked or allowed
		// defaults to false
		ClientIsolation bool `yaml:"clientIsolation"`
		// DisableIPTables configures whether to disable iptables configuration completely
		// defaults to false
		DisableIPTables bool `yaml:"disableIPTables"`
	} `yaml:"vpn"`
	// Configure the embedded DNS server
	DNS struct {
		// Enabled allows you to turn on/off
		// the VPN DNS proxy feature.
		// DNS Proxying is enabled by default.
		Enabled bool `yaml:"enabled"`
		// Upstream configures the addresses of upstream
		// DNS servers to which client DNS requests will be sent to.
		// NOTE: currently wg-access-server will always prefer the first upstream and fall back on failures.
		// Defaults the host's upstream DNS servers (via resolvconf)
		// or Cloudflare DNS if resolvconf cannot be used.
		Upstream []string `yaml:"upstream"`
		// Domain sets a domain that the embedded dns server should serve authoritatively for device addresses.
		// A and AAAA queries for names in the format <device>.<user>.<domain> will be answered with the IP addresses
		// of the according device. Queries for <domain> will be answered with the VPN server address.
		// Example domain: 'vpn.home.arpa.'
		// Disabled by default.
		Domain string `yaml:"domain"`
	} `yaml:"dns"`
	// Configures settings in the configuration file distributed to clients, either by download, or QR-code.
	ClientConfig struct {
		// DNS servers to be provided with the client configuration file.
		// These are written into the configuration file as is.
		// If left empty the server decides about the address; usually the wg-access-server address.
		// If not empty, these replace the wg-access-servers DNS addresses.
		// Empty by default.
		DNSServers []string `yaml:"dnsServers"`
		// Search domain to be provided with the client configuration file.
		// Empty by default.
		DNSSearchDomain string `yaml:"dnsSearchDomain"`
		// The maximum transmission unit (MTU) to be written into the client configuration file.
		// If left empty "the MTU is automatically determined from the endpoint addresses or the system default route,
		// which is usually a sane choice." (From wg-quick 8 manual page.)
		// Empty by default.
		MTU int `yaml:"mtu"`
		// The default persistent keepalive interval for all clients.
		// If set, this value will be used as the default in the web UI.
		// Users can still override this value per device.
		// Defaults to 0 (disabled)
		PersistentKeepalive int `yaml:"PersistentKeepalive"`
	} `yaml:"clientConfig"`
	// Metrics configures access to the /metrics endpoint.
	Metrics struct {
		BasicAuth struct {
			// Username required when accessing /metrics. Empty disables auth.
			Username string `yaml:"username"`
			// Bcrypt hashed password required when accessing /metrics.
			PasswordHash string `yaml:"passwordHash"`
		} `yaml:"basicAuth"`
	} `yaml:"metrics"`
	// Auth configures optional authentication backends
	// to control access to the web ui.
	// Devices will be managed on a per-user basis if any
	// auth backends are configured.
	// If no authentication backends are configured then
	// the server will not require any authentication.
	Auth authconfig.AuthConfig `yaml:"auth"`
	// HTTPS configuration
	HTTPS struct {
		// Enable HTTPS for the web UI
		// Defaults to true
		Enabled bool `yaml:"enabled"`
		// Path to the TLS certificate file
		// If not provided, a self-signed certificate will be generated
		CertFile string `yaml:"certFile"`
		// Path to the TLS private key file
		// If not provided, a self-signed certificate will be generated
		KeyFile string `yaml:"keyFile"`
		// Port for HTTPS server
		// Defaults to 8443
		Port int `yaml:"port"`
		// Listen host for HTTPS server
		// Defaults to "" (all hosts)
		Host string `yaml:"host"`
	} `yaml:"https"`
}

// AmneziaConfig contains the stable protocol profile shared by the server and
// client. Server and client sections intentionally contain only their own
// protocol fields; S1-S4 and H1-H4 are shared.
type AmneziaConfig struct {
	Shared AmneziaSharedConfig `yaml:"shared"`
	Server AmneziaServerConfig `yaml:"server"`
	Client AmneziaClientConfig `yaml:"client"`
}

type AmneziaSharedConfig struct {
	S1 uint32 `yaml:"s1"`
	S2 uint32 `yaml:"s2"`
	S3 uint32 `yaml:"s3"`
	S4 uint32 `yaml:"s4"`
	H1 string `yaml:"h1"`
	H2 string `yaml:"h2"`
	H3 string `yaml:"h3"`
	H4 string `yaml:"h4"`
}

type AmneziaServerConfig struct {
	HeaderProtectionKey string `yaml:"headerProtectionKey"`
}

type AmneziaClientConfig struct {
	JC                     uint32 `yaml:"jc"`
	JMin                   uint32 `yaml:"jmin"`
	JMax                   uint32 `yaml:"jmax"`
	I1                     string `yaml:"i1"`
	I2                     string `yaml:"i2"`
	I3                     string `yaml:"i3"`
	I4                     string `yaml:"i4"`
	I5                     string `yaml:"i5"`
	ContentPaddingAddition string `yaml:"contentPaddingAddition"`
	RekeyAfterTime         string `yaml:"rekeyAfterTime"`
	RekeyTimeout           string `yaml:"rekeyTimeout"`
	RejectAfterTime        string `yaml:"rejectAfterTime"`
	KeepaliveTimeout       string `yaml:"keepaliveTimeout"`
	MaxHandshakeAttempts   string `yaml:"maxHandshakeAttempts"`
}

func awgUint(v uint32) *uint32 {
	if v == 0 {
		return nil
	}
	return &v
}

func awgString(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

// ServerDeviceConfig translates application configuration to the adapter's
// server-side configuration in one place.
func (c AmneziaConfig) ServerDeviceConfig() amnezia.AWGConfig {
	return amnezia.AWGConfig{
		S1: awgUint(c.Shared.S1), S2: awgUint(c.Shared.S2), S3: awgUint(c.Shared.S3), S4: awgUint(c.Shared.S4),
		H1: awgString(c.Shared.H1), H2: awgString(c.Shared.H2), H3: awgString(c.Shared.H3), H4: awgString(c.Shared.H4),
		HeaderProtectionKey: c.Server.HeaderProtectionKey,
	}
}

var awgRange = regexp.MustCompile(`^(\d+)(?:-(\d+))?$`)

func validateAWGRange(name, value string) (uint64, uint64, error) {
	if value == "" {
		return 0, 0, nil
	}
	m := awgRange.FindStringSubmatch(strings.TrimSpace(value))
	if m == nil {
		return 0, 0, fmt.Errorf("amnezia %s must be a single number or range", name)
	}
	lo, _ := strconv.ParseUint(m[1], 10, 64)
	hi := lo
	if m[2] != "" {
		hi, _ = strconv.ParseUint(m[2], 10, 64)
	}
	if lo > hi {
		return 0, 0, fmt.Errorf("amnezia %s range is reversed", name)
	}
	return lo, hi, nil
}

// Validate checks application-level constraints before the device is created.
func (c AmneziaConfig) Validate() error {
	if c.Client.JMin > 0 && c.Client.JMax > 0 && c.Client.JMin > c.Client.JMax {
		return fmt.Errorf("amnezia jmin must be <= jmax")
	}
	if c.Server.HeaderProtectionKey != "" {
		if _, err := wgtypes.ParseKey(c.Server.HeaderProtectionKey); err != nil {
			return fmt.Errorf("amnezia headerProtectionKey is invalid: %w", err)
		}
		for name, value := range map[string]uint32{"s1": c.Shared.S1, "s2": c.Shared.S2, "s3": c.Shared.S3, "s4": c.Shared.S4} {
			if value < 8 {
				return fmt.Errorf("amnezia %s must be at least 8 when headerProtectionKey is enabled", name)
			}
		}
	}
	ranges := []struct{ name, value string }{{"h1", c.Shared.H1}, {"h2", c.Shared.H2}, {"h3", c.Shared.H3}, {"h4", c.Shared.H4}, {"contentPaddingAddition", c.Client.ContentPaddingAddition}, {"rekeyAfterTime", c.Client.RekeyAfterTime}, {"rekeyTimeout", c.Client.RekeyTimeout}, {"rejectAfterTime", c.Client.RejectAfterTime}, {"keepaliveTimeout", c.Client.KeepaliveTimeout}, {"maxHandshakeAttempts", c.Client.MaxHandshakeAttempts}}
	var h [][2]uint64
	for _, r := range ranges {
		lo, hi, err := validateAWGRange(r.name, r.value)
		if err != nil {
			return err
		}
		if strings.HasPrefix(r.name, "h") && r.value != "" {
			for _, prior := range h {
				if lo <= prior[1] && prior[0] <= hi {
					return fmt.Errorf("amnezia %s overlaps another H range", r.name)
				}
			}
			h = append(h, [2]uint64{lo, hi})
		}
	}
	return nil
}
