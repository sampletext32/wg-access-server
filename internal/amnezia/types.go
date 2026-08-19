package amnezia

import (
	"net"
	"net/netip"
	"time"
)

// AWGConfig contains the server-side values sent to amneziawg-go over UAPI.
type AWGConfig struct {
	JC, JMin, JMax                                                                                                *uint32
	S1, S2, S3, S4                                                                                                *uint32
	H1, H2, H3, H4                                                                                                *string
	I1, I2, I3, I4, I5                                                                                            *string
	HeaderProtectionKey                                                                                           string
	ContentPaddingAddition, RekeyAfterTime, RekeyTimeout, RejectAfterTime, KeepaliveTimeout, MaxHandshakeAttempts *string
}

type DeviceConfig struct {
	PrivateKey string
	Address    []string
	ListenPort int
	MTU        int
	AWG        AWGConfig
}

type Peer struct {
	PublicKey                   string
	Endpoint                    *net.UDPAddr
	AllowedIPs                  []netip.Prefix
	LastHandshakeTime           time.Time
	ReceiveBytes, TransmitBytes int64
}

type Interface interface {
	Configure(DeviceConfig) error
	AddPeer(publicKey, presharedKey string, addressCIDR []string) error
	ListPeers() ([]Peer, error)
	RemovePeer(publicKey string) error
	PublicKey() (string, error)
	Ping() error
	Close() error
}

type Options struct {
	InterfaceName string
	SocketPath    string
	ChildPath     string
}
