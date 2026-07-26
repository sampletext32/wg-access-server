package services

import (
	"context"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/sampletext32/amneziawg-embed/pkg/wgembed"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/freifunkMUC/wg-access-server/buildinfo"
	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/internal/network"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

type ServerService struct {
	proto.UnimplementedServerServer
	Config *config.AppConfig
	Wg     wgembed.WireGuardInterface
}

func (s *ServerService) Info(ctx context.Context, req *proto.InfoReq) (*proto.InfoRes, error) {
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "not authenticated")
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
		ctxlogrus.Extract(ctx).Error(err)
		return nil, status.Errorf(codes.Internal, "failed to get public key")
	}

	vpnip, vpnipv6, err := network.ServerVPNIPs(s.Config.VPN.CIDR, s.Config.VPN.CIDRv6)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get server IPs")
	}
	dnsAddress := network.StringJoinIPs(vpnip, vpnipv6)

	var hostVPNIP string
	if vpnip.IsValid() {
		hostVPNIP = vpnip.Addr().String()
	} else {
		hostVPNIP = ""
	}

	return &proto.InfoRes{
		Host:      stringValue(&host),
		PublicKey: publicKey,
		Port:      int32(s.Config.WireGuard.Port),
		// TODO IPv6 what is HostVpnIp used for, do we need HostVpnIpv6 as well?
		HostVpnIp:                       hostVPNIP,
		MetadataEnabled:                 s.Config.EnableMetadata,
		InactiveDeviceDeletionEnabled:   s.Config.EnableInactiveDeviceDeletion,
		InactiveDeviceGracePeriod:       DurationToDurationpb(&s.Config.InactiveDeviceGracePeriod),
		IsAdmin:                         user.Claims.IsAdmin(),
		AllowedIps:                      allowedIPs(s.Config),
		DnsEnabled:                      s.Config.DNS.Enabled,
		DnsAddress:                      dnsAddress,
		Filename:                        s.Config.Filename,
		ClientConfigDnsServers:          clientConfigDnsServers(s.Config),
		ClientConfigDnsSearchDomain:     s.Config.ClientConfig.DNSSearchDomain,
		ClientConfigMtu:                 int32(s.Config.ClientConfig.MTU),
		ClientConfigPersistentKeepalive: int32(s.Config.ClientConfig.PersistentKeepalive),
		BuildInfo:                       &proto.BuildInfo{Version: buildinfo.Version(), Commit: buildinfo.ShortCommitHash()},
		Mtu:                             int32(s.Config.WireGuard.MTU),
		AmneziaJc:                       s.Config.Amnezia.Client.JC,
		AmneziaJmin:                     s.Config.Amnezia.Client.JMin,
		AmneziaJmax:                     s.Config.Amnezia.Client.JMax,
		AmneziaS1:                       s.Config.Amnezia.Shared.S1,
		AmneziaS2:                       s.Config.Amnezia.Shared.S2,
		AmneziaS3:                       s.Config.Amnezia.Shared.S3,
		AmneziaS4:                       s.Config.Amnezia.Shared.S4,
		AmneziaH1:                       s.Config.Amnezia.Shared.H1,
		AmneziaH2:                       s.Config.Amnezia.Shared.H2,
		AmneziaH3:                       s.Config.Amnezia.Shared.H3,
		AmneziaH4:                       s.Config.Amnezia.Shared.H4,
		AmneziaI1:                       s.Config.Amnezia.Client.I1,
		AmneziaI2:                       s.Config.Amnezia.Client.I2,
		AmneziaI3:                       s.Config.Amnezia.Client.I3,
		AmneziaI4:                       s.Config.Amnezia.Client.I4,
		AmneziaI5:                       s.Config.Amnezia.Client.I5,
		AmneziaContentPaddingAddition:   s.Config.Amnezia.Client.ContentPaddingAddition,
		AmneziaRekeyAfterTime:           s.Config.Amnezia.Client.RekeyAfterTime,
		AmneziaRekeyTimeout:             s.Config.Amnezia.Client.RekeyTimeout,
		AmneziaRejectAfterTime:          s.Config.Amnezia.Client.RejectAfterTime,
		AmneziaKeepaliveTimeout:         s.Config.Amnezia.Client.KeepaliveTimeout,
		AmneziaMaxHandshakeAttempts:     s.Config.Amnezia.Client.MaxHandshakeAttempts,
	}, nil
}

func allowedIPs(config *config.AppConfig) string {
	return strings.Join(config.VPN.AllowedIPs, ", ")
}

func clientConfigDnsServers(config *config.AppConfig) string {
	return strings.Join(config.ClientConfig.DNSServers, ", ")
}
