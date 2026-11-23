package serve

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/xray"
)

// newVLESS prepares the second dataplane without starting it. A server that
// does not serve VLESS gets nil, and the device manager is given the no-op
// implementation instead, so nothing downstream has to ask whether the feature
// is on.
//
// It is separate from the start because of the order: the device manager has to
// know about every device before the process is started, so that the first
// configuration it reads already carries them all. Starting it first would mean
// one API call per device at boot, and a server with a few thousand devices
// would spend that time adding users it could have written down.
func newVLESS(conf *config.AppConfig) (*xray.Server, func()) {
	if !conf.VLESS.Enabled {
		logrus.Info("VLESS is disabled")
		return nil, func() {}
	}
	server, err := xray.New(conf.VLESS)
	if err != nil {
		// The WireGuard interface is already up at this point. Refusing to
		// start the whole server because the second protocol could not
		// create its directory would take the working one down with it.
		logrus.Error(fmt.Errorf("failed to prepare VLESS: %w", err))
		return nil, func() {}
	}
	return server, func() {
		if err := server.Close(); err != nil {
			logrus.Error(fmt.Errorf("failed to stop VLESS: %w", err))
		}
	}
}

// vlessDataplane adapts the Xray process to what the device manager needs. The
// counter types of the two packages hold the same two numbers on purpose, but
// they belong to different packages: converting here keeps the device manager
// from importing the Xray one, and keeps the Xray one from knowing about
// devices.
type vlessDataplane struct {
	server *xray.Server
}

func (p vlessDataplane) Upsert(id string) error { return p.server.Upsert(id) }
func (p vlessDataplane) Remove(id string) error { return p.server.Remove(id) }

func (p vlessDataplane) Counters() (map[string]devices.ProxyTraffic, error) {
	counters, err := p.server.Stats()
	if err != nil {
		return nil, err
	}
	converted := make(map[string]devices.ProxyTraffic, len(counters))
	for id, traffic := range counters {
		converted[id] = devices.ProxyTraffic{Uplink: traffic.Uplink, Downlink: traffic.Downlink}
	}
	return converted, nil
}

// disabledProxy is what a server without VLESS gives the device manager: no
// users, no counters, nothing to keep in sync.
type disabledProxy struct{}

func (disabledProxy) Upsert(string) error { return nil }
func (disabledProxy) Remove(string) error { return nil }
func (disabledProxy) Counters() (map[string]devices.ProxyTraffic, error) {
	return map[string]devices.ProxyTraffic{}, nil
}
