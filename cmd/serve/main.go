// Package serve runs the server: it reads the configuration, brings up the
// WireGuard interface, the DNS proxy and the web server, and takes them down
// again in the order they came up.
package serve

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/buildinfo"
	"github.com/freifunkMUC/wg-access-server/internal/authnz"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/internal/websessions"
)

func (cmd *servecmd) Name() string {
	return "serve"
}

func (cmd *servecmd) Run() {
	// Swallow any panic stacktrace
	defer func() {
		if err := recover(); err != nil {
			logrus.Fatal(err)
		}
	}()

	conf := cmd.ReadConfig()

	// Software banner
	logrus.Infof("+++ wg-access-server %s (%s)", buildinfo.Version(), buildinfo.ShortCommitHash())

	vpn := vpnAddresses(conf)

	wg, stopWireGuard, err := cmd.startWireGuard(conf, vpn)
	defer stopWireGuard()
	if err != nil {
		logrus.Error(err)
		return
	}

	// Storage
	storageBackend, err := storage.NewStorage(conf.Storage)
	if err != nil {
		logrus.Error(fmt.Errorf("failed to create storage backend: %w", err))
		return
	}
	if err := storageBackend.Open(); err != nil {
		logrus.Error(fmt.Errorf("failed to connect/open storage backend: %w", err))
		return
	}
	defer storageBackend.Close()

	// Device manager
	//
	// The second protocol, VLESS, is prepared here and started after the
	// initial sync below: the device manager fills it with the devices that
	// already exist, so the process reads one configuration that is complete
	// instead of being told about every device one call at a time.
	vless, stopVLESS := newVLESS(conf)
	defer stopVLESS()

	var proxy devices.ProxyDataplane = disabledProxy{}
	if vless != nil {
		proxy = vlessDataplane{server: vless}
	}

	deviceManager := devices.New(wg, storageBackend, conf.VPN.CIDR, conf.VPN.CIDRv6,
		devices.WithMaxDevicesPerUser(conf.MaxDevicesPerUser),
		devices.WithFirewallSync(firewallSync(conf, vpn)),
		devices.WithProxyDataplane(proxy))

	stopDNS, err := startDNS(conf, deviceManager, storageBackend, vpn)
	defer stopDNS()
	if err != nil {
		logrus.Error(err)
		return
	}

	// Cancelled on shutdown, which stops the background loops of the device
	// manager before the storage backend is closed under them.
	backgroundCtx, stopBackground := context.WithCancel(context.Background())
	defer stopBackground()

	if err := deviceManager.StartSync(backgroundCtx, conf.EnableMetadata, conf.EnableInactiveDeviceDeletion, conf.InactiveDeviceGracePeriod); err != nil {
		logrus.Error(fmt.Errorf("failed to sync: %w", err))
		return
	}

	// Only now is the list of devices known, so only now can the VLESS
	// process be started with all of them in its configuration. A failure is
	// logged and not fatal: the WireGuard interface is up and serving, and
	// taking that down because the second protocol could not start would
	// remove a working VPN for a feature nobody may be using yet.
	if vless != nil {
		if err := vless.Start(backgroundCtx); err != nil {
			logrus.Error(fmt.Errorf("failed to start VLESS; it will not be available until the server is restarted: %w", err))
		}
	}

	// The browser sessions: the cookie carries an id, who signed in is kept
	// here. Expired ones are removed while the server runs.
	maxAge, err := authnz.SessionMaxAge(conf.Auth.SessionStore)
	if err != nil {
		logrus.Error(err)
		return
	}
	browserSessions := websessions.New(storageBackend, maxAge)
	browserSessions.StartCleanup(backgroundCtx)

	handler, err := newRouter(conf, deviceManager, storageBackend, wg, browserSessions)
	if err != nil {
		logrus.Error(err)
		return
	}

	if err := listenAndServe(conf, handler, stopBackground); err != nil {
		logrus.Error(err)
	}
}
