package serve

import (
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// removeStaleInterface deletes the interface called name if it is one this
// server could have created. One found at startup is left over from a run that
// did not clean up; creating it again would fail with "file exists".
//
// Only a WireGuard-family link is removed: the kernel module's "amneziawg"
// device, a TUN device from the userspace fallback, or the stock "wireguard"
// one an earlier version of this server made. Deleting whatever happens to
// carry the name is how a pod on the host network takes the node's own
// interface with it, so a foreign link type is refused rather than removed.
func removeStaleInterface(
	name string,
	linkByName func(string) (netlink.Link, error),
	linkDel func(netlink.Link) error,
) error {
	link, err := linkByName(name)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}
		return fmt.Errorf("failed to look up interface %s: %w", name, err)
	}

	if linkType := link.Type(); !wireGuardLinkType(linkType) {
		return fmt.Errorf(
			"refusing to remove %s: it is a %q interface, not one this server creates", name, linkType)
	}

	logrus.Warnf("removing stale interface %s left over from a previous run", name)
	if err := linkDel(link); err != nil {
		return fmt.Errorf("failed to remove stale interface %s: %w", name, err)
	}
	return nil
}

// wireGuardLinkType reports whether a netlink link type is one this server's
// dataplane can produce. "amneziawg" is the kernel module, "tun" the userspace
// fallback's device, and "wireguard" a stock interface left by an older version
// of the server - all three are ours to replace.
func wireGuardLinkType(linkType string) bool {
	switch linkType {
	case "amneziawg", "wireguard", "tun":
		return true
	default:
		return false
	}
}
