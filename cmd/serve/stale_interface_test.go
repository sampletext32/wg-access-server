package serve

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
)

// testWGLink is a link of a type this server can create. The device the tests
// use before it only cares about the name, not what kind of link it is.
func testWGLink(name string) netlink.Link {
	return &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name}, LinkType: "amneziawg"}
}

func TestRemoveStaleInterfaceDeletesExistingLink(t *testing.T) {
	var deleted []string
	err := removeStaleInterface("wg0",
		func(name string) (netlink.Link, error) { return testWGLink(name), nil },
		func(l netlink.Link) error { deleted = append(deleted, l.Attrs().Name); return nil },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deleted) != 1 || deleted[0] != "wg0" {
		t.Fatalf("deleted %v, want [wg0]", deleted)
	}
}

// An interface of an unrelated kind that happens to carry our name is not ours
// to delete - that is how a hostNetwork pod would take the node's own link.
func TestRemoveStaleInterfaceRefusesForeignType(t *testing.T) {
	err := removeStaleInterface("awg0",
		func(name string) (netlink.Link, error) {
			return &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name}, LinkType: "bridge"}, nil
		},
		func(netlink.Link) error { t.Fatal("must not delete a foreign link"); return nil },
	)
	if err == nil {
		t.Fatal("a foreign link type was deleted")
	}
}

func TestWireGuardLinkType(t *testing.T) {
	for _, linkType := range []string{"amneziawg", "wireguard", "tun"} {
		if !wireGuardLinkType(linkType) {
			t.Errorf("%q must be treated as ours", linkType)
		}
	}
	for _, linkType := range []string{"bridge", "veth", "device", "", "none"} {
		if wireGuardLinkType(linkType) {
			t.Errorf("%q must not be treated as ours", linkType)
		}
	}
}

func TestRemoveStaleInterfaceNothingToRemove(t *testing.T) {
	err := removeStaleInterface("wg0",
		func(string) (netlink.Link, error) { return nil, netlink.LinkNotFoundError{} },
		func(netlink.Link) error { t.Fatal("must not delete anything"); return nil },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRemoveStaleInterfaceLookupFailure(t *testing.T) {
	boom := errors.New("boom")
	err := removeStaleInterface("wg0",
		func(string) (netlink.Link, error) { return nil, boom },
		func(netlink.Link) error { t.Fatal("must not delete anything"); return nil },
	)
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want it to wrap %v", err, boom)
	}
}

func TestRemoveStaleInterfaceDeleteFailure(t *testing.T) {
	boom := errors.New("boom")
	err := removeStaleInterface("wg0",
		func(name string) (netlink.Link, error) { return testWGLink(name), nil },
		func(netlink.Link) error { return boom },
	)
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want it to wrap %v", err, boom)
	}
}
