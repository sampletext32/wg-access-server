# Docker

Load the `ip_tables` and `ip6_tables` kernel modules on the host. The
AmneziaWG dataplane runs in userspace and does not use the `wireguard` module.

```bash
modprobe ip_tables && modprobe ip6_tables
# Load modules on boot
echo ip_tables >> /etc/modules
echo ip6_tables >> /etc/modules
```

```bash
docker run \
  -it \
  --rm \
  --cap-add NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  --sysctl net.ipv6.conf.all.forwarding=1 \
  -v wg-access-server-data:/data \
  -e "WG_ADMIN_PASSWORD=$WG_ADMIN_PASSWORD" \
  -e "WG_WIREGUARD_PRIVATE_KEY=$WG_WIREGUARD_PRIVATE_KEY" \
  -p 8443:8443/tcp \
  -p 51820:51820/udp \
  ghcr.io/freifunkmuc/wg-access-server:latest
```

## Modules

With `WG_VPN_FIREWALL=nftables`, load `nf_tables` instead of `ip_tables` and `ip6_tables`.

If you are unable to load the `iptables` kernel modules, you can add the `SYS_MODULE` capability instead: `--cap-add SYS_MODULE`. You must also add the following mount: `-v /lib/modules:/lib/modules:ro`.

This is not recommended as it essentially gives the container root privileges over the host system and an attacker could easily break out of the container.

The AmneziaWG dataplane in this fork is userspace: it does not use the
WireGuard kernel module, so there is nothing to load and no kernel-to-userspace
fallback. `/dev/net/tun` and `NET_ADMIN` are what it needs.

## IPv6-only (without IPv4)

If you don't want IPv4 inside the VPN network, set `WG_VPN_CIDR=0`.

```bash
docker run \
  -it \
  --rm \
  --cap-add NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  --sysctl net.ipv6.conf.all.forwarding=1 \
  -v wg-access-server-data:/data \
  -e "WG_ADMIN_PASSWORD=$WG_ADMIN_PASSWORD" \
  -e "WG_WIREGUARD_PRIVATE_KEY=$WG_WIREGUARD_PRIVATE_KEY" \
  -e "WG_VPN_CIDR=0" \
  -p 8443:8443/tcp \
  -p 51820:51820/udp \
  ghcr.io/freifunkmuc/wg-access-server:latest
```

## IPv4-only (without IPv6)

If you don't want IPv6 inside the VPN network, set `WG_VPN_CIDRV6=0`.
In this case you can also get rid of the sysctls:

```bash
docker run \
  -it \
  --rm \
  --cap-add NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  -v wg-access-server-data:/data \
  -e "WG_ADMIN_PASSWORD=$WG_ADMIN_PASSWORD" \
  -e "WG_WIREGUARD_PRIVATE_KEY=$WG_WIREGUARD_PRIVATE_KEY" \
  -e "WG_VPN_CIDRV6=0" \
  -p 8443:8443/tcp \
  -p 51820:51820/udp \
  ghcr.io/freifunkmuc/wg-access-server:latest
```
