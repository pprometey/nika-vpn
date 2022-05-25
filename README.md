# Nika-VPN

It is an easy to deploy and use private VPN server with ad blocker.

This VPN service based on Wirehole + wg-access-server and provides a convenient and friendly installer.

1. [Wirehole](https://github.com/IAmStoxe/wirehole) - WireHole is a combination of WireGuard, Pi-hole, and Unbound in a docker-compose project with the intent of enabling users to quickly and easily create a personally managed full or split-tunnel WireGuard VPN with ad blocking capabilities thanks to Pi-hole, and DNS caching, additional privacy options, and upstream providers via Unbound.
2. [wg-access-server](https://github.com/freifunkMUC/wg-access-server) - An all-in-one WireGuard VPN solution with a web ui for connecting devices.

Winguard from Wirehole replaced with wg-access-server.

This VPN service has been developed and tesed for Oracle Cloud Free Tier on configurations:

- Canonical-Ubuntu-20.04-Minimal, VM.Standard.E2.1.Micro (amd64)
- Canonical-Ubuntu-20.04, VM.Standard.A1.Flex (aarch64)

## Installation

This script is meant for quick & easy install via:  

`curl -sSL https://bit.ly/nika-vpn-install | sh`  
or:  
`wget -qO- https://bit.ly/nika-vpn-install | sh` 

Once it ends, you need to go to `[server_public_ip_address]:[vpn_control_panel_port]` to create VPN users.

To reinstall, or specify additional script execution arguments, you need to add the `-s -` key to `sh`, for example:

`curl -sSL https://bit.ly/nika-vpn-install | sh -s - --force`  
or:  
`wget -qO- https://bit.ly/nika-vpn-install | sh -s - -f` 

## Nika-VPN Installer CLI Overview

You can also see this information by running  
`curl -sSL https://bit.ly/nika-vpn-install | sh -s - --help`  
or  
`wget -qO- https://bit.ly/nika-vpn-install | sh -s - -h`  
from the command line.

```
Installing a personal private VPN server with ad blocker

Usage:
  nika-vpn-install.sh [-d <arg>...] [-q] [--logLevel <level>...] [options]
  nika-vpn-install.sh -h|--help

Options:
  -h, --help
        Displays current help for command line options
  -q, --quiet
        This tries its best to reduce output by suppressing the script's own
        messages and passing "quiet" arguments to tools that support them
  -f, --force
        Reinstalling the Nika-VPN service if it is already installed
  -d, --dest DEST
        Nika-VPn installation directory, default '${HOME}/nika-vpn'
  -tz, --time-zone TIME_ZONE
        Setting the time zone for Nika-VPN modules, by default 'Etc/UTC'
  -ss, --services-subnet SERVICES_SUBNET
        The IPv4 network range for Nika-VPN modules, default '10.43.0.0/24'
  -ul, --unbound-local-ip UNBOUND_LOCAL_IP
        IPv4 local address of the Unbound server DNS module, default '10.43.0.2'

  -pl, --pihole-local-ip PI_HOLE_LOCAL_IP
        IPv4 local address of the Pi-Hole ad blocker module, default '10.43.0.3'
  -pp, --pihole-password PI_HOLE_PASSWORD
        Password to access the Pi-Hole ad blocker control panel

  -wl, --wg-local-ip WG_LOCAL_IP
        IPv4 local address of wg-access-server VPN server module,
        default '10.43.0.4'
  -wpk, --wg-private-key WG_WIREGUARD_PRIVATE_KEY
        The wireguard private key. This value is required and must be stable.
        If this value changes all devices must re-register. If not defined,
        generated automatically.
  -au, --admin-username WG_ADMIN_USERNAME
        The admin account username for wg-access-server, default 'admin@vpn'
  -ap, --admin-password WG_ADMIN_PASSWORD
        The admin account password for wg-access-server.If not defined,
        generated automatically
  -pv, --port-vpn WG_WIREGUARD_PORT
        Wireguard server port (udp), for connecting VPN clients, default '51820'
  -pa, --port-admin WG_PORT
        Web interface port for administration VPN server wg-access-server (http)
        default '8000'
  -ll, --log-level WG_LOG_LEVEL
        The global log level for wg-access-server, possible values
        (trace|debug|info|error|fatal), default 'info'
  -ws, --wg-storage WG_STORAGE
        A storage backend connection string for wg-access-server,
        default 'sqlite3:///data/db.sqlite3'
  -dm, --disable-metadata
        Turn off collection of device metadata logging for wg-access-server.
        Includes last handshake time and RX/TX bytes only.
  -сf, --config-filename
        Change the name of the configuration file the user can download
        (do not include the '.conf' extension ), default 'NikaVpnClient'
  -wi, --wg-interface
        The wireguard network interface name, default 'wg0'
  -vc, --vpn-cidr WG_VPN_CIDR
        The VPN IPv4 network range. VPN clients will be assigned IP addresses
        in this range. Set to 0 to disable IPv4. Default '10.44.0.0/24'
  -vc6, --vpn-cidrv6
        The VPN IPv6 network range. VPN clients will be assigned IP addresses
        in this range. Set to 0 to disable IPv6. Defalt '0'
  -nd, --nat-disabled
        Disables NAT for IPv4 for wg-access-server
  -ne6, --nat-enable-v6
        Enable NAT for IPv6 for wg-access-server
  -ai, --allowed-ips
        Allowed IPs that clients may route through this VPN. This will be set
        in the client's WireGuard connection file and routing is also enforced
        by the server using iptables. Default '0.0.0.0/0,::/0'
  -dd, --dns-disabled
        Enable/disable the embedded DNS proxy server. This is enabled by default
        and allows VPN clients to avoid DNS leaks by sending all DNS requests to
        wg-access-server itself.
  -dn, --dns-domain WG_DNS_DOMAIN
        A domain to serve configured devices authoritatively. Queries for names
        in the format .. will be answered with the device's IP addresses.
  -eh, --external-host WG_EXTERNAL_HOST
        The external domain for the server (e.g. vpn.example.com)
  -ci, --client-isolation
        BLock or allow traffic between client devices (client isolation)
  -wf, --without_firewall
        Without installing 'firewalld' and opening ports                       
```

## Screenshots

### Wireguard Access Portal

![Wireguard Access Porta](content/wg-access-server.png "Wireguard Access Porta")

### Pi-hole dashboard

![Pi-hole dashboard](content/pi-hole.png "Pi-hole dashboard")

## Health check

To check the correct installation and operation of Nika-VPN, use the services:

- DNS leak test - [dnsleak.com](https://dnsleak.com/) or [ipleak.net](https://ipleak.net/)
- Сheck ad blocking - [canyoublockit.com](https://canyoublockit.com)

## TODO

- [ ] Obfuscate VPN traffic with Shadowsocks or WebSocket Tunneling
- [ ] Secure traffic via tls (https) and use ODIC authorization for Wireguard Access Server using Traefik and Authelia
