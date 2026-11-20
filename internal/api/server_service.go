package api

import (
	"context"
	"slices"
	"strings"

	"connectrpc.com/connect"
	"github.com/sampletext32/amneziawg-embed/pkg/wgembed"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/freifunkMUC/wg-access-server/buildinfo"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authconfig"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/network"
	"github.com/freifunkMUC/wg-access-server/internal/users"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

type ServerService struct {
	Config *config.AppConfig
	Wg     wgembed.WireGuardInterface
	// DeviceManager is where the networks routed through devices come from.
	// They belong in the client configurations: a client that tunnels only
	// what it is told to would otherwise never send anything to a site
	// behind another device.
	DeviceManager *devices.DeviceManager
	// PasswordChange is whether the server keeps passwords at all - it does
	// when a built-in provider is configured. Whether this session's own
	// password is one of them is decided per request.
	PasswordChange bool
	// TwoFactor is the second factor of the built-in sign-in, nil when the
	// server keeps none.
	TwoFactor *users.TwoFactor
	// Passkeys are the other second factor, nil for the same reason.
	Passkeys *users.Passkeys
}

func passkeyCount(passkeys *users.Passkeys, subject string) int32 {
	if passkeys == nil {
		return 0
	}
	registered, err := passkeys.List(subject)
	if err != nil {
		return 0
	}
	return int32(len(registered))
}

func recoveryCodesLeft(twoFactor *users.TwoFactor, subject string) int32 {
	if twoFactor == nil {
		return 0
	}
	return int32(twoFactor.RecoveryCodesLeft(subject))
}

func (s *ServerService) Info(ctx context.Context, _ *connect.Request[proto.InfoReq]) (*connect.Response[proto.InfoRes], error) {
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, errNotAuthenticated()
	}

	host := s.Config.ExternalHost
	if strings.Contains(host, ":") {
		if !strings.HasPrefix(host, "[") {
			host = "[" + host
		}
		if !strings.HasSuffix(host, "]") {
			host = host + "]"
		}
	}

	publicKey, err := s.Wg.PublicKey()
	if err != nil {
		return nil, internalError(ctx, err, "failed to get public key")
	}

	vpnip, vpnipv6, err := network.ServerVPNIPs(s.Config.VPN.CIDR, s.Config.VPN.CIDRv6)
	if err != nil {
		return nil, internalError(ctx, err, "failed to get server IPs")
	}
	dnsAddress := network.StringJoinIPs(vpnip, vpnipv6)

	return connect.NewResponse(&proto.InfoRes{
		Host:                            stringValue(&host),
		PublicKey:                       publicKey,
		Port:                            int32(s.Config.WireGuard.Port),
		MetadataEnabled:                 s.Config.EnableMetadata,
		InactiveDeviceDeletionEnabled:   s.Config.EnableInactiveDeviceDeletion,
		InactiveDeviceGracePeriod:       durationToDurationpb(&s.Config.InactiveDeviceGracePeriod),
		IsAdmin:                         user.Claims.IsAdmin(),
		AllowedIps:                      s.allowedIPs(),
		DnsEnabled:                      s.Config.DNS.Enabled,
		DnsAddress:                      dnsAddress,
		Filename:                        s.Config.Filename,
		ClientConfigDnsServers:          clientConfigDnsServers(s.Config),
		ClientConfigDnsSearchDomain:     s.Config.ClientConfig.DNSSearchDomain,
		ClientConfigMtu:                 int32(s.Config.ClientConfig.MTU),
		ClientConfigPersistentKeepalive: int32(s.Config.ClientConfig.PersistentKeepalive),
		BuildInfo:                       &proto.BuildInfo{Version: buildinfo.Version(), Commit: buildinfo.ShortCommitHash()},
		Mtu:                             int32(s.Config.WireGuard.MTU),
		ApiTokensEnabled:                s.Config.EnableAPITokens,
		ApiTokenMaxLifetime:             apiTokenMaxLifetime(s.Config),
		Subject:                         user.Subject,
		PasswordChangeEnabled:           s.PasswordChange && authconfig.HasPassword(user.Provider),
		TwoFactorEnabled:                s.TwoFactor != nil && s.TwoFactor.Enabled(user.Subject),
		RecoveryCodesLeft:               recoveryCodesLeft(s.TwoFactor, user.Subject),
		Passkeys:                        passkeyCount(s.Passkeys, user.Subject),
		UserDisplayName:                 user.Name,
		UserProvider:                    user.Provider,
		Amnezia:                         amneziaClientConfig(s.Config.Amnezia),
	}), nil
}

// apiTokenMaxLifetime is the cap on API tokens, unset for none.
func apiTokenMaxLifetime(conf *config.AppConfig) *durationpb.Duration {
	if conf.APITokenMaxLifetime <= 0 {
		return nil
	}
	return durationToDurationpb(&conf.APITokenMaxLifetime)
}

// allowedIPs is what a new client configuration will tunnel: the configured
// networks and whatever is routed through the devices. A configuration that
// was downloaded earlier does not learn about a route added later - the user
// has to fetch it again, or add the network by hand.
func (s *ServerService) allowedIPs() string {
	allowed := append([]string{}, s.Config.VPN.AllowedIPs...)
	if s.DeviceManager != nil {
		for _, routed := range s.DeviceManager.RoutedNetworks() {
			if !slices.Contains(allowed, routed) {
				allowed = append(allowed, routed)
			}
		}
	}
	return strings.Join(allowed, ", ")
}

func clientConfigDnsServers(config *config.AppConfig) string {
	return strings.Join(config.ClientConfig.DNSServers, ", ")
}

// amneziaClientConfig is the part of the AmneziaWG profile a client needs. It
// is nil when no profile is configured, in which case a configuration file is
// a plain WireGuard one.
//
// The header protection key is included: AmneziaWG encrypts the packet header
// with a key both ends have, so a client without it cannot read anything from
// this server. It is not per-device data - every client gets the same key,
// like the padding and the header ranges.
func amneziaClientConfig(a config.AmneziaConfig) *proto.AmneziaClientConfig {
	if a.IsZero() {
		return nil
	}
	return &proto.AmneziaClientConfig{
		Jc:                     a.Client.JC,
		Jmin:                   a.Client.JMin,
		Jmax:                   a.Client.JMax,
		S1:                     a.Shared.S1,
		S2:                     a.Shared.S2,
		S3:                     a.Shared.S3,
		S4:                     a.Shared.S4,
		H1:                     a.Shared.H1,
		H2:                     a.Shared.H2,
		H3:                     a.Shared.H3,
		H4:                     a.Shared.H4,
		I1:                     a.Client.I1,
		I2:                     a.Client.I2,
		I3:                     a.Client.I3,
		I4:                     a.Client.I4,
		I5:                     a.Client.I5,
		ContentPaddingAddition: a.Shared.ContentPaddingAddition,
		RekeyAfterTime:         a.Client.RekeyAfterTime,
		RekeyTimeout:           a.Client.RekeyTimeout,
		RejectAfterTime:        a.Client.RejectAfterTime,
		KeepaliveTimeout:       a.Client.KeepaliveTimeout,
		MaxHandshakeAttempts:   a.Client.MaxHandshakeAttempts,
		HeaderProtectionKey:    a.Server.HeaderProtectionKey,
		RandomTrailers:         a.Shared.RandomTrailers,
		DisableCookies:         a.Shared.DisableCookies,
	}
}
