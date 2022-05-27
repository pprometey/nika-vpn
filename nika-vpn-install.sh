#!/bin/sh -e
#
# Nika-VPN installation script.
#
# Repository: https://github.com/pprometey/nika-vpn
#
# This script is meant for quick & easy install via:
#   'curl -sSL https://bit.ly/nika-vpn-install | sh'
# or:
#   'wget -qO- https://bit.ly/nika-vpn-install | sh'
#
# Arguments (use `... | sh -s - ARGUMENTS`)
#
# -h: Show help message.
# -q: reduce script's output
# -f: force over-write even if 'nika-vpn' already installed
# -d DESTDIR: change destination directory
#
# Copyright (c) 2018 Alexei Chernyavski. Released under the MIT License.priva

REPO_URL="https://github.com/pprometey/nika-vpn.git"
PROJECT_NAME="nika-vpn"
DEFAULT_DEST="${HOME}/${PROJECT_NAME}"
NIKA_VPN_INFO_FILENAME=".${PROJECT_NAME}-info"
NIKA_VPN_ENV_FILENAME=".env"
DEST="" # -d|--dest _
FORCE="" # -f|--force
QUIET="" # -q|--quiet
NIKA_VPN_TEMP_DIR=

TIME_ZONE="Etc/UTC" # -tz|--time-zone _
SERVICES_SUBNET="10.43.0.0/24" # -ss|--services-subnet _
UNBOUND_LOCAL_IP="10.43.0.2" # -ul|--unbound-local-ip _
PI_HOLE_LOCAL_IP="10.43.0.3" # -pl|--pihole-local-ip _
PI_HOLE_PASSWORD= # -pp|--pihole-password _

WG_LOCAL_IP="10.43.0.4" # -wl|--wg-local-ip _
WG_WIREGUARD_PRIVATE_KEY= # -wpk|--wg-private-key _
WG_ADMIN_USERNAME="admin@vpn" # -au|--admin-username _
WG_ADMIN_PASSWORD= # -ap|--admin-password _
WG_WIREGUARD_PORT="51820" # -pv|--port-vpn _
WG_PORT="8000" # -pa|--port-admin _
WG_LOG_LEVEL="info" # -ll|--log-level _
WG_STORAGE="sqlite3:///data/db.sqlite3" # -ws|--wg-storage _
WG_DISABLE_METADATA="false" # -dm|--disable-metadata
WG_FILENAME="NikaVpnClient" # -сf|--config-filename _
WG_WIREGUARD_INTERFACE="wg0" # -wi|--wg-interface _
WG_VPN_CIDR="10.44.0.0/24" # -vc|--vpn-cidr
WG_VPN_CIDRV6="0" # -vc6|--vpn-cidrv6 _
WG_IPV4_NAT_ENABLED="true" # -nd|--nat-disabled
WG_IPV6_NAT_ENABLED="false" # -ne6|--nat-enable-v6
WG_VPN_ALLOWED_IPS="0.0.0.0/0,::/0" # -ai|--allowed-ips _
WG_DNS_ENABLED="true" # -dd|--dns-disabled
WG_DNS_DOMAIN="" # -dn|--dns-domain _
WG_EXTERNAL_HOST="" # -eh|--external-host _
WG_VPN_CLIENT_ISOLATION="false" # -ci|--client-isolation

WITH_FIREWALL="true" # -wf|--without_firewall

WSTUNNEL_DOWNLOAD_URL="https://github.com/erebe/wstunnel/releases/download/v4.1"
WSTUNNEL_LINUX_AARCH64_FN="wstunnel-aarch64-linux.zip"
WSTUNNEL_LINUX_X64_FN="wstunnel-x64-linux"
WSTUNEL_WS_PORT="443" # -pw|--port-web-socket _
WSTUNNEL_ENABLED="true" # -wd|--web-socket-disabled
WSTUNNEL_SERVICE="wstunnel.service"

# -------------------------------------------------------------------------------

# print a message to stdout unless '-q' passed to script
info() {
  if [ -z "$QUIET" ] ; then
    echo "$@"
  fi
}

# print a message to stderr and exit with error code
die() {
  echo "$@" >&2
  exit 1
}

# print a separator
print_separator() {
  info ""
  info "----------------------------------------------------------------"
  info ""
}

to_lowercase() {
  echo $1 | sed 's/./\L&/g'
}

to_uppercase() {
  echo $1 | sed 's/./\U&/g'
}

generate_password() {
  echo $(tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1)
}

get_env_value() {
  grep "${1}" ${2} | cut -d'=' -f2
}

get_subnet_prefix() {
  echo ${1%.*}
}

# creates a temporary directory, which will be cleaned up automatically
# when the script finishes
make_temp_dir() {
  NIKA_VPN_TEMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t ${PROJECT_NAME})"
}

# cleanup the temporary directory if it's been created.  called automatically
# when the script exits.
cleanup_temp_dir() {
  if [ -n "$NIKA_VPN_TEMP_DIR" ] ; then
    rm -rf "$NIKA_VPN_TEMP_DIR"
    NIKA_VPN_TEMP_DIR=
  fi
}

# get in which directory this script is run
get_run_path() {
  readlink -f $0 | xargs dirname
}

# -------------------------------------------------------------------------------

# Adds a 'sudo' prefix if sudo is available to execute the given command
# If not, the given command is run as is
# When requesting root permission, always show the command and never re-use cached credentials.
sudocmd() {
  reason="$1"; shift
  if command -v sudo >/dev/null; then
    echo "Running command as root for $reason."
    echo "     $@"
    sudo "$@"
  else
    "$@"
  fi
}

# Check whether the given command exists
has_cmd() {
  command -v "$1" > /dev/null 2>&1
}

# Check whether 'sudo' command exists
has_sudo() {
  has_cmd sudo
}

# Check whether 'perl' command exists
has_perl() {
  has_cmd perl
}

# Check whether 'wget' command exists
has_wget() {
  has_cmd wget
}

# Check whether 'curl' command exists
has_curl() {
  has_cmd curl
}

# Check whether 'lsb_release' command exists
has_lsb_release() {
  has_cmd lsb_release
}

# Check whether 'getconf' command exists
has_getconf() {
  has_cmd getconf
}

has_apt_get() {
  has_cmd apt-get
}

has_docker() {
  has_cmd docker
}

has_gnupg() {
  has_cmd gnupg
}

has_git() {
  has_cmd git
}

has_unzip() {
  has_cmd unzip
}

has_timedatectl() {
  has_cmd timedatectl
}

has_systemctl() {
  has_cmd systemctl
}

has_firewalld() {
  has_cmd firewalld
}

has_systemd_detect_virt() {
  has_cmd systemd-detect-virt
}

has_unattended_upgrades() {
  has_cmd unattended-upgrades
}

has_dialog() {
  has_cmd dialog
}

has_wstunnel() {
  has_cmd wstunnel
}

# -------------------------------------------------------------------------------

get_public_ip() {
  if ! has_curl && ! has_wget ; then
    if ! try_install_pkgs curl wget; then
      die "Neither wget nor curl is available, please install one to continue."
    fi
  fi
  public_ip=$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || \
    curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")

  if ! echo $public_ip | grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
    die "Could not determine public IP address."
  fi
}


# Check for 'curl' or 'wget' and attempt to install 'curl' if neither found,
# or fail the script if that is not possible.
check_dl_tools() {
  if ! has_curl && ! has_wget ; then
    if ! try_install_pkgs curl wget; then
      die "Neither wget nor curl is available, please install one to continue."
    fi
  fi
}

# Download a URL to file using 'curl' or 'wget'.
dl_to_file() {
  check_dl_tools
  if ! wget ${QUIET:+-q} "-O$2" "$1"; then
    info "wget download failed: $1, try download with curl..."
    if ! curl ${QUIET:+-sS} -L -o "$2" "$1"; then
      die "curl download failed: $1"
    fi
  fi
}

dl_to_stdout() {
  if ! has_curl ; then
    if ! try_install_pkgs curl ; then
      die "curl is not available, please install one to continue."
    fi
  fi
  if ! curl -fsSL "$1" 2>/dev/null; then
    die "curl download failed: $1"
  fi
}

unzip_to_dir() {
  if ! has_unzip ; then
    if ! try_install_pkgs unzip ; then
      die "unzip is not available, please install one to continue."
    fi
  fi
  if ! unzip ${QUIET:+-q} -o "$1" -d "$2" ; then
    die "unzip failed: $1 to $2"
  fi
}

# -------------------------------------------------------------------------------

show_help() {
  nika_vpn_help_file=${NIKA_VPN_TEMP_DIR}/.nika_vpn_help
cat << EOF > $nika_vpn_help_file
Installing a personal private VPN server with ad blocker

Usage:
  nika-vpn-install.sh [-d <arg>...] [-q] [--logLevel <level>...] [options]
  nika-vpn-install.sh -h|--help

Options:
  -h, --help
        Display this help and exit.
  -q, --quiet
        This tries its best to reduce output by suppressing the script's own
        messages and passing "quiet" arguments to tools that support them.
  -f, --force
        Reinstalling the Nika-VPN service if it is already installed.
  -d, --dest DEST
        Nika-VPn installation directory, default '\${HOME}/nika-vpn'.
  -tz, --time-zone TIME_ZONE
        Setting the time zone for Nika-VPN modules, by default 'Etc/UTC'.
  -ss, --services-subnet SERVICES_SUBNET
        The IPv4 network range for Nika-VPN modules, default '10.43.0.0/24'.
  -ul, --unbound-local-ip UNBOUND_LOCAL_IP
        IPv4 local address of the Unbound server DNS module,
        by default '10.43.0.2'.

  -pl, --pihole-local-ip PI_HOLE_LOCAL_IP
        IPv4 local address of the Pi-Hole ad blocker module, default '10.43.0.3'
  -pp, --pihole-password PI_HOLE_PASSWORD
        Password to access the Pi-Hole ad blocker control panel.

  -wl, --wg-local-ip WG_LOCAL_IP
        IPv4 local address of wg-access-server VPN server module,
        default '10.43.0.4'.
  -wpk, --wg-private-key WG_WIREGUARD_PRIVATE_KEY
        The wireguard private key. This value is required and must be stable.
        If this value changes all devices must re-register. If not defined,
        generated automatically.
  -au, --admin-username WG_ADMIN_USERNAME
        The admin account username for wg-access-server, default 'admin@vpn'.
  -ap, --admin-password WG_ADMIN_PASSWORD
        The admin account password for wg-access-server.If not defined,
        generated automatically.
  -pv, --port-vpn WG_WIREGUARD_PORT
        Wireguard server port (udp), for connecting VPN clients,
        default '51820'.
  -pa, --port-admin WG_PORT
        Web interface port for administration VPN server
        wg-access-server (http).
        default '8000'.
  -ll, --log-level WG_LOG_LEVEL
        The global log level for wg-access-server, possible values
        (trace|debug|info|error|fatal), default 'info'.
  -ws, --wg-storage WG_STORAGE
        A storage backend connection string for wg-access-server,
        default 'sqlite3:///data/db.sqlite3'.
  -dm, --disable-metadata
        Turn off collection of device metadata logging for wg-access-server.
        Includes last handshake time and RX/TX bytes only.
  -сf, --config-filename
        Change the name of the configuration file the user can download
        (do not include the '.conf' extension ), default 'NikaVpnClient'.
  -wi, --wg-interface
        The wireguard network interface name, default 'wg0'.
  -vc, --vpn-cidr WG_VPN_CIDR
        The VPN IPv4 network range. VPN clients will be assigned IP addresses
        in this range. Set to 0 to disable IPv4. Default '10.44.0.0/24'.
  -vc6, --vpn-cidrv6
        The VPN IPv6 network range. VPN clients will be assigned IP addresses
        in this range. Set to 0 to disable IPv6. Defalt '0'.
  -nd, --nat-disabled
        Disables NAT for IPv4 for wg-access-server.
  -ne6, --nat-enable-v6
        Enable NAT for IPv6 for wg-access-server.
  -ai, --allowed-ips
        Allowed IPs that clients may route through this VPN. This will be set
        in the client's WireGuard connection file and routing is also enforced
        by the server using iptables. Default '0.0.0.0/0,::/0'.
  -dd, --dns-disabled
        Enable/disable the embedded DNS proxy server. This is enabled by default
        and allows VPN clients to avoid DNS leaks by sending all DNS requests to
        wg-access-server itself.
  -dn, --dns-domain WG_DNS_DOMAIN
        A domain to serve configured devices authoritatively. Queries for names
        in the format .. will be answered with the device's IP addresses.
  -eh, --external-host WG_EXTERNAL_HOST
        The external domain for the server (e.g. vpn.example.com).
  -ci, --client-isolation
        BLock or allow traffic between client devices (client isolation).
  -wf, --without_firewall
        Without installing 'firewalld' and opening ports.

  -wd,--web-socket-disabled
        Don't set up a websocket tunnel. This is enabled by default.
  -pw,--port-web-socket WSTUNEL_WS_PORT
        Websocket tunnel listening port.

EOF

cat $nika_vpn_help_file | more
}

show_error_invalid_argument_value() {
  echo "For argument $1, value $2 is invalid" >&2
  exit 1
}

validate_timezone() {
  timedatectl list-timezones --no-pager | grep -q "$1"
}

set_timezone() {
  if has_timedatectl ; then
    if validate_timezone $1 ; then
      TIME_ZONE=$1
    else
      return 1
    fi
  else
    die "timedatectl not available."
  fi
}

validate_port() {
 if echo "$1" | grep -Eq '^[0-9]{1,5}$'; then
     if [ $1 -gt 0 ] && [ $1 -lt 65535 ] ; then
       return 0
     else
       return 1
     fi
 else
   return 1
 fi
}

set_vpn_port() {
  if validate_port $1 ; then
    WG_WIREGUARD_PORT=$1
  else
    return 1
  fi
}

set_admin_port() {
  if validate_port $1 ; then
    WG_PORT=$1
  else
    return 1
  fi
}

validate_subnet() {
  echo $1 | grep -Eq '(^[0-2][0-5]{1,2}?\.|^[3-9][0-9]?\.)([0-2][0-5]{1,2}?\.|[3-9][0-9]?\.)([0-2][0-5]{1,2}?\.|[3-9][0-9]?\.)([0-2][0-5]{1,2}?\/|[3-9][0-9]?\/)([1-9]|[1-2][\d]|3[0-2])$'
}

set_service_subnet() {
  if validate_subnet $1 ; then
    SERVICE_SUBNET=$1
  else
    return 1
  fi
}

set_vpn_cidr() {
  if validate_subnet $1 ; then
    WG_VPN_CIDR=$1
  else
    return 1
  fi
}

validate_ipv4() {
  echo $1 | grep -Eq '(^[0-2][0-5]{1,2}?\.|^[3-9][0-9]?\.)([0-2][0-5]{1,2}?\.|[3-9][0-9]?\.)([0-2][0-5]{1,2}?\.|[3-9][0-9]?\.)([0-2][0-5]{1,2}?$|[3-9][0-9]?$)'
}

set_unbound_local_ip() {
  if validate_ipv4 $1 ; then
    UNBOUND_LOCAL_IP=$1
  else
    return 1
  fi
}

set_pihole_local_ip() {
  if validate_ipv4 $1 ; then
    PI_HOLE_LOCAL_IP=$1
  else
    return 1
  fi
}

set_wg_local_ip() {
  if validate_ipv4 $1 ; then
    WG_LOCAL_IP=$1
  else
    return 1
  fi
}

validate_log_level() {
 echo $1 | grep -Eq '^(trace|debug|info|error|fatal)$'
}

set_log_level() {
  if validate_log_level $1 ; then
    LOG_LEVEL=$1
  else
    return 1
  fi
}

validate_domain_name() {
  echo "$1" | grep -Eq '^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
}

set_dns_domain() {
  if validate_domain_name $1 ; then
    WG_DNS_DOMAIN=$1
  else
    return 1
  fi
}

set_external_host() {
  if validate_domain_name $1 ; then
    WG_EXTERNAL_HOST=$1
  else
    return 1
  fi
}

set_web_socket_port() {
  if validate_port $1 ; then
    WSTUNEL_WS_PORT=$1
  else
    return 1
  fi
}
# -------------------------------------------------------------------------------

# Install packages using apt-get
apt_get_install_pkgs() {
  missing=
  for pkg in $*; do
    if ! dpkg -s $pkg 2>/dev/null | grep '^Status:.*installed' >/dev/null; then
      missing="$missing $pkg"
    fi
  done
  if [ "$missing" = "" ]; then
    info "Already installed!"
  elif ! sudocmd "install required system dependencies" apt-get install -y ${QUIET:+-qq}$missing; then
    die "\nInstalling apt packages failed.  Please run 'apt-get update' and try again."
  fi
}

# Attempt to install packages using whichever of apt-get, dnf, yum, or apk is
# available.
try_install_pkgs() {
  if has_apt_get ; then
    apt_get_install_pkgs "$@"
  # elif has_dnf ; then
  #   dnf_install_pkgs "$@"
  # elif has_yum ; then
  #   yum_install_pkgs "$@"
  # elif has_apk ; then
  #   apk_install_pkgs "$@"
  else
    return 1
  fi
}

# -------------------------------------------------------------------------------

# determines the the CPU's instruction set
get_isa() {
  if arch | grep -Eq 'armv[78]l?' ; then
    echo arm
  elif arch | grep -q aarch64 ; then
    echo aarch64
  else
    echo x86
  fi
}

# determines 64- or 32-bit architecture
# if getconf is available, it will return the arch of the OS, as desired
# if not, it will use uname to get the arch of the CPU, though the installed
# OS could be 32-bits on a 64-bit CPU
get_arch() {
  if has_getconf ; then
    if getconf LONG_BIT | grep -q 64 ; then
      echo 64
    else
      echo 32
    fi
  else
    case "$(uname -m)" in
      *64)
        echo 64
        ;;
      *)
        echo 32
        ;;
    esac
  fi
}

# exits with code 0 if arm ISA is detected as described above
is_arm() {
  test "$(get_isa)" = arm
}

# exits with code 0 if aarch64 ISA is detected as described above
is_aarch64() {
  test "$(get_isa)" = aarch64
}

# exits with code 0 if a x86_64-bit architecture is detected as described above
is_x86_64() {
  test "$(get_arch)" = 64 -a "$(get_isa)" = "x86"
}

# Attempts to determine the running Linux distribution.
# Prints "DISTRO;VERSION" (distribution name and version)"."
distro_info() {
  parse_lsb() {
    lsb_release -a 2> /dev/null | perl -ne "$1"
  }

  try_lsb() {
    if has_lsb_release ; then
      TL_DIST="$(parse_lsb 'if(/Distributor ID:\s+([^ ]+)/) { print "\L$1"; }')"
      TL_VERSION="$(parse_lsb 'if(/Release:\s+([^ ]+)/) { print "\L$1"; }')"
      echo "$TL_DIST;$TL_VERSION"
    else
      return 1
    fi
  }

  try_release() {
    parse_release() {
      perl -ne "$1" /etc/*release 2>/dev/null
    }

    parse_release_id() {
      parse_release 'if(/^(DISTRIB_)?ID\s*=\s*"?([^"]+)/) { print "\L$2"; exit 0; }'
    }

    parse_release_version() {
      parse_release 'if(/^(DISTRIB_RELEASE|VERSION_ID)\s*=\s*"?([^"]+)/) { print $2; exit 0; }'
    }

    TR_RELEASE="$(parse_release_id);$(parse_release_version)"

    if [ ";" = "$TR_RELEASE" ] ; then
      if [ -e /etc/arch-release ] ; then
        # /etc/arch-release exists but is often empty
        echo "arch;"
      elif [ -e /etc/centos-release ] && grep -q "\<6\>" /etc/centos-release ; then
        # /etc/centos-release has a non-standard format before version 7
        echo "centos;6"
      else
        return 1
      fi
    else
      echo "$TR_RELEASE"
    fi
  }

  try_issue() {
    case "$(cat /etc/issue 2>/dev/null)" in
      "Arch Linux"*)
        echo "arch;" # n.b. Version is not available in /etc/issue on Arch
        ;;
      "Ubuntu"*)
        echo "ubuntu;$(perl -ne 'if(/Ubuntu (\d+\.\d+)/) { print $1; }' < /etc/issue)"
        ;;
      "Debian"*)
        echo "debian;$(perl -ne 'if(/Debian GNU\/Linux (\d+(\.\d+)?)/) { print $1; }' < /etc/issue)"
        ;;
      *"SUSE"*)
        echo "suse;$(perl -ne 'if(/SUSE\b.* (\d+\.\d+)/) { print $1; }' < /etc/issue)"
        ;;
      *"NixOS"*)
        echo "nixos;$(perl -ne 'if(/NixOS (\d+\.\d+)/) { print $1; }' < /etc/issue)"
        ;;
      "CentOS"*)
        echo "centos;$(perl -ne 'if(/^CentOS release (\d+)\./) { print $1; }' < /etc/issue)"
        ;;
      *)
    esac
    # others do not output useful info in issue, return empty
  }

  try_lsb || try_release || try_issue
}

get_distro_name() {
  echo "$(distro_info | cut -d';' -f1)"
}

# -------------------------------------------------------------------------------

print_result() {
  if [ -z "$QUIET" ] ; then
    nika_vpn_info_file=${NIKA_VPN_TEMP_DIR}/${NIKA_VPN_INFO_FILENAME}
    cat << EOF > $nika_vpn_info_file
****************************************************************

To create users and connect to VPN, go to the VPN server
administration panel at:

VPN control panel address: $(get_public_ip):$WG_PORT
Login: $WG_ADMIN_USERNAME
Password: $WG_ADMIN_PASSWORD

----------------------------------------------------------------

To manage the Pi-hole ad blocker, after connecting via VPN,
go to the administration panel at:
Pi-hole dashboard: http://$PI_HOLE_LOCAL_IP/admin
Password: $PI_HOLE_PASSWORD

EOF

    if [ "$WSTUNNEL_ENABLED" = "true" ] ; then
      cat << EOF >> $nika_vpn_info_file
----------------------------------------------------------------

Websockets tunnel to connect to VPN listens on port: $WSTUNEL_WS_PORT
EOF
    fi

    cat << EOF >> $nika_vpn_info_file

****************************************************************
EOF

    cat $nika_vpn_info_file
  fi
}

create_wstunnel_service() {
  if [ $WSTUNNEL_ENABLED = "true" ]; then
    cat << EOF > $NIKA_VPN_TEMP_DIR/$WSTUNNEL_SERVICE
[Unit]
Description=Tunnel WireGuard UDP over websocket
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/wstunnel -v --server wss://0.0.0.0:${WSTUNEL_WS_PORT} --restrictTo=127.0.0.1:${WG_WIREGUARD_PORT}
Restart=no

[Install]
WantedBy=multi-user.target
EOF

    if ! sudocmd "create wstunnel unit file" mv $NIKA_VPN_TEMP_DIR/$WSTUNNEL_SERVICE /etc/systemd/system/$WSTUNNEL_SERVICE; then
      die "Failed to create wstunnel service"
    fi
    if ! sudocmd "enable wstunnel service" systemctl enable --now $WSTUNNEL_SERVICE; then
      die "Failed to enable wstunnel service"
    fi
  fi
}

delete_wstunnel_service() {

  if systemctl is-active $WSTUNNEL_SERVICE | grep -q "active" ; then
    if ! sudocmd "stop wstunnel service" systemctl stop $WSTUNNEL_SERVICE; then
      die "Failed to stop wstunnel service"
    fi
  fi

  if systemctl is-enabled $WSTUNNEL_SERVICE | grep -q "enabled" ; then
    if ! sudocmd "disable wstunnel service" systemctl disable $WSTUNNEL_SERVICE; then
      die "Failed to disable wstunnel service"
    fi
  fi

  if systemctl list-unit-files | grep -q "$WSTUNNEL_SERVICE" ; then
    if ! sudocmd "delete wstunnel unit file" rm /etc/systemd/system/$WSTUNNEL_SERVICE; then
      die "Failed to delete wstunnel unit file"
    fi
  fi
}

apt_open_ports() {
  if [ $WITH_FIREWALL = "true" ]; then
    if ! sudocmd "open udp port $WG_WIREGUARD_PORT" firewall-cmd --permanent --zone=public --add-port=$WG_WIREGUARD_PORT/udp ${QUIET:+-q}; then
      die "\nOpening port for VPN connection failed."
    fi

    if ! sudocmd "open tcp port $WG_PORT" firewall-cmd --permanent --zone=public --add-port=$WG_PORT/tcp ${QUIET:+-q}; then
      die "\nOpening port for VPN administration failed."
    fi

    if [ "$WSTUNNEL_ENABLED" = "true" ] ; then
      if ! sudocmd "open tcp port $WSTUNEL_WS_PORT" firewall-cmd --permanent --zone=public --add-port=$WSTUNEL_WS_PORT/tcp ${QUIET:+-q}; then
        die "\nOpening port for tunneling via web-socket failed."
      fi
    fi

    if ! sudocmd "restart firewall" firewall-cmd --reload ${QUIET:+-q}; then
      die "\nRestarting firewall failed."
    fi
  fi
}

apt_close_ports() {
  if ! sudocmd "close udp port $1" firewall-cmd --permanent --zone=public --remove-port=$1/udp ${QUIET:+-q}; then
    die "\nClosing port failed. Please run 'sudo firewall-cmd --permanent --zone=public --add-port=$1/udp' and try again."
  fi

  if ! sudocmd "close tcp port $2" firewall-cmd --permanent --zone=public --remove-port=$2/tcp ${QUIET:+-q}; then
    die "\nClosing port failed. Please run 'sudo firewall-cmd --permanent --zone=public --add-port=$2/tcp' and try again."
  fi

  if [ -n "$3" ]; then
    if ! sudocmd "close tcp port $3" firewall-cmd --permanent --zone=public --remove-port=$3/tcp ${QUIET:+-q}; then
      die "\nClosing port failed. Please run 'sudo firewall-cmd --permanent --zone=public --add-port=$3/tcp' and try again."
    fi
  fi

  if ! sudocmd "restart firewall" firewall-cmd --reload ${QUIET:+-q}; then
    die "\nRestarting firewall failed. Please run 'sudo firewall-cmd --reload' and try again."
  fi
}

set_blank_dest() {
    [ "${DEST}" = "" ] && DEST=$DEFAULT_DEST
}

apt_clone_repository() {
  if ! has_git ; then
    info "Installing git..."
    info ""
    apt_get_install_pkgs git
  fi

  set_blank_dest

  if [ -d ${DEST} ]; then
    die "\nDestination folder is exist. Remove folder and try again. \n'rm -rf ${DEST}'"
  fi

  info "Cloning repository..."
  info ""
  if ! git clone ${REPO_URL} ${DEST} ${QUIET:+-q}; then
    die "\nCloning repository failed. "
  fi
}

create_env_file() {
  if [ -d ${DEST} ]; then
cat << EOF > ${DEST}/${NIKA_VPN_ENV_FILENAME}
TIME_ZONE=${TIME_ZONE}
SERVICES_SUBNET=${SERVICES_SUBNET}
UNBOUND_LOCAL_IP=${UNBOUND_LOCAL_IP}
PI_HOLE_LOCAL_IP=${PI_HOLE_LOCAL_IP}
PI_HOLE_PASSWORD=${PI_HOLE_PASSWORD}
WG_LOCAL_IP=${WG_LOCAL_IP}
WG_WIREGUARD_PRIVATE_KEY=${WG_WIREGUARD_PRIVATE_KEY}
WG_ADMIN_USERNAME=${WG_ADMIN_USERNAME}
WG_ADMIN_PASSWORD=${WG_ADMIN_PASSWORD}
WG_WIREGUARD_PORT=${WG_WIREGUARD_PORT}
WG_PORT=${WG_PORT}
WG_LOG_LEVEL=${WG_LOG_LEVEL}
WG_STORAGE=${WG_STORAGE}
WG_DISABLE_METADATA=${WG_DISABLE_METADATA}
WG_FILENAME=${WG_FILENAME}
WG_WIREGUARD_INTERFACE=${WG_WIREGUARD_INTERFACE}
WG_VPN_CIDR=${WG_VPN_CIDR}
WG_VPN_CIDRV6=${WG_VPN_CIDRV6}
WG_IPV4_NAT_ENABLED=${WG_IPV4_NAT_ENABLED}
WG_IPV6_NAT_ENABLED=${WG_IPV6_NAT_ENABLED}
WG_VPN_ALLOWED_IPS=${WG_VPN_ALLOWED_IPS}
WG_DNS_ENABLED=${WG_DNS_ENABLED}
WG_DNS_UPSTREAM=${PI_HOLE_LOCAL_IP}
WG_DNS_DOMAIN=${WG_DNS_DOMAIN}
WG_EXTERNAL_HOST=${WG_EXTERNAL_HOST}
WG_VPN_CLIENT_ISOLATION=${WG_VPN_CLIENT_ISOLATION}
WSTUNEL_WS_PORT=${WSTUNEL_WS_PORT}
EOF
fi
}

get_wireguard_private_key() {
  if ! has_docker ; then
    die "Docker is not installed. Please install Docker and try again."
  fi
  sudo docker run --rm ghcr.io/freifunkmuc/wg-access-server wg genkey
}


set_blank_params() {
    [ "$WG_WIREGUARD_PRIVATE_KEY" = "" ] && WG_WIREGUARD_PRIVATE_KEY=$(get_wireguard_private_key)
    [ "$WG_ADMIN_PASSWORD" = "" ] && WG_ADMIN_PASSWORD=$(generate_password)
}

run_services() {
  if [ -d ${DEST} ]; then
    info "Running services..."
    info ""
    set_blank_params
    create_env_file
    if sudocmd "run services" docker compose -f "${DEST}/docker-compose.yml" up -d ${QUIET:+--quiet-pull}; then
      return 0
    else
      return 1
    fi
  else
    return 1
  fi
}

apt_install_wstunnel() {

  if [ "$WSTUNNEL_ENABLED" = "true" ]; then
    if ! has_wstunnel; then
        info ""
        info "Installing wstunnel..."
        info ""

        download_wstunnel() {
          dl_to_file "$WSTUNNEL_DOWNLOAD_URL/$1" "$NIKA_VPN_TEMP_DIR/$1"
        }

        add_wstunnel_command() {
          if ! sudocmd "add wstunnel command" mv "$NIKA_VPN_TEMP_DIR/$1" /usr/local/bin/wstunnel; then
            die "Failed to add wstunnel command"
          fi
          if ! sudocmd "set permissions for wstunnel command" chmod uo+x /usr/local/bin/wstunnel; then
            die "Failed to set permissions for wstunnel command"
          fi
          if ! sudocmd "set privileges for wstunnel" setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/wstunnel; then
            die "Failed to set privileges for wstunnel"
          fi
        }

        add_wstunnel_command_x64() {
          download_wstunnel $1
          add_wstunnel_command "$1"
        }

        add_wstunnel_command_aarch64() {
          download_wstunnel $1

          if ! unzip_to_dir "$NIKA_VPN_TEMP_DIR/$1" "$NIKA_VPN_TEMP_DIR"; then
            die "Failed to unzip wstunnel"
          fi

          add_wstunnel_command "wstunnel_aarch64"
        }

        if is_x86_64 ; then
          add_wstunnel_command_x64 $WSTUNNEL_LINUX_X64_FN
        elif is_aarch64 ; then
          add_wstunnel_command_aarch64 $WSTUNNEL_LINUX_AARCH64_FN
        fi

        if ! has_wstunnel; then
          die "Failed to install wstunnel. Please install manually."
        fi
    fi
  fi
}

# Download packages information from all configured sources
apt_update_packges_info() {
  if ! sudocmd "update packages list" apt-get update -y ${QUIET:+-qq}; then
    die "\nUpdating package list failed.  Please run 'apt-get update' and try again."
  fi
}

is_docker_active() {
  if has_docker; then
    if systemctl show --property ActiveState docker | grep -q 'ActiveState=active'; then
      return 0
    else
      return 1
    fi
  else
    return 1
  fi
}

apt_docker_install() {
  add_docker_repository() {
    add_docker_gpg_key() {
      save_docker_gpg_key() {
        if ! sudocmd "add Docker’s official GPG key" gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg ; then
          die "\nAdding Docker’s official GPG key failed."
        fi
      }

      dl_to_stdout "https://download.docker.com/linux/$(get_distro_name)/gpg" | save_docker_gpg_key
    }

    add_docker_source_list_file() {
      save_docker_source_list() {
        if ! sudocmd "add Docker repository" tee /etc/apt/sources.list.d/docker.list > /dev/null ; then
          die "\nAdding Docker repository failed."
        fi
      }
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
https://download.docker.com/linux/$(get_distro_name) $(lsb_release -cs) stable" | save_docker_source_list
    }

    [ ! -e "/usr/share/keyrings/docker-archive-keyring.gpg" ] && add_docker_gpg_key
    [ ! -e "/etc/apt/sources.list.d/docker.list" ] && add_docker_source_list_file
  }

  if ! has_docker ; then
    info ""
    info "Installing docker..."
    info ""
    add_docker_repository
    apt_update_packges_info
    apt_get_install_pkgs docker-ce docker-ce-cli containerd.io docker-compose-plugin

    if  ! is_docker_active ; then
      if ! sudocmd "activate docker" systemctl start docker ; then
        die "\nStarting docker failed. Please run 'sudo systemctl start docker' and try again."
      fi
    fi
  fi
}

apt_firewalld_install() {
  is_enabled_firewalld() {
    if [ "$(systemctl is-enabled firewalld)" = "enabled" ]; then
      return 0
    else
      return 1
    fi
  }

  is_active_firewalld() {
    if [ "$(systemctl is-active firewalld)" = "active" ]; then
      return 0
    else
      return 1
    fi
  }

  if [ $WITH_FIREWALL = "true" ]; then
    if ! has_firewalld; then
      info ""
      info "Installing firewalld..."
      info ""
      apt_update_packges_info
      apt_get_install_pkgs firewalld
    fi

    if ! is_enabled_firewalld; then
      info ""
      info "Enabling firewalld..."
      info ""
      if ! sudocmd "enable firewalld" systemctl enable firewalld ${QUIET:+-q}; then
        die "\nEnabling firewalld failed. Please run 'sudo systemctl enable firewalld' and try again."
      fi
    fi

    if ! is_active_firewalld; then
      info "Starting firewalld..."
      info ""
      systemctl start firewalld
      if ! sudocmd "start firewalld" systemctl start firewalld ${QUIET:+-q}; then
        die "\nStarting firewalld failed. Please run 'sudo systemctl start firewalld' and try again."
      fi
    fi
  fi
}

apt_upgrade() {
  if ! sudocmd "upgrade OS" apt-get upgrade -y ${QUIET:+-qq}; then
    die "\nUpdating package list failed.  Please run 'apt-get upgrade' and try again."
  fi
}

# Install dependencies for distros that use Apt
apt_install_dependencies() {
    if ! has_curl  || \
       ! has_gnupg  || \
       ! has_lsb_release  || \
       ! has_git  || \
       ! has_unzip ; then
      info ""
      info "Installing dependencies..."
      info ""
      apt_update_packges_info
      apt_get_install_pkgs dialog
      apt_upgrade
      apt_get_install_pkgs ca-certificates curl gnupg lsb-release git unzip dnsutils net-tools nano screen
    fi
}

do_apt_install() {
  install_dependencies() {
    apt_install_dependencies
    apt_firewalld_install
    apt_docker_install
    apt_install_wstunnel
  }

  install_sevices() {
    print_separator
    install_dependencies
    print_separator
    apt_clone_repository
    print_separator
    run_services
    print_separator
    apt_open_ports
    create_wstunnel_service
    print_separator
    print_result
  }

  if is_x86_64 || is_aarch64 ; then
    install_sevices
  # elif is_arm ; then
    #install_dependencies
  else
    die "Sorry, currently only 64-bit (x86_64, aarch64) Linux binary is available."
  fi
}

# Attempt to install on a Linux distribution
do_distro() {
  if ! has_perl; then
    if ! try_install_pkgs perl; then
      #TODO: remove dependence on 'perl', which is not installed by default
      #on some distributions (Fedora and RHEL, in particular).
      die "This script requires 'perl', please install it to continue."
    fi
  fi

  IFS=";" read -r DISTRO VERSION <<GETDISTRO
$(distro_info)
GETDISTRO

  if [ -n "$DISTRO" ] ; then
    info ""
    info "Detected Linux distribution: $DISTRO"
  fi

  case "$DISTRO" in
    ubuntu|linuxmint|elementary|neon|pop)
      do_apt_install "$VERSION"
      ;;
    debian|kali|raspbian|mx)
      do_apt_install "$VERSION"
      ;;
    fedora)
      # do_fedora_install "$VERSION"
      ;;
    centos|rhel|redhatenterpriseserver)
      # do_centos_install "$VERSION"
      ;;
    alpine)
      # do_alpine_install "$VERSION"
      ;;
    *)
      # do_sloppy_install
  esac
}

linux_can_install() {
  if has_systemd_detect_virt; then
    if [ "$( systemd-detect-virt )" = "openvz" ]; then
        die "OpenVZ virtualization is not supported"
    fi
  fi
}

# Determine operating system and attempt to install.
do_os() {
  case "$(uname)" in
    "Linux")
      linux_can_install
      do_distro
      ;;
    # "Darwin")
    #   do_osx_install
    #   ;;
    *)
      die "Sorry, this installer does not support your operating system: $(uname)."
  esac
}

has_nika_vpn() {
  if ! has_sudo; then
    die "This script requires 'sudo' installed."
  fi
  if has_docker && is_docker_active; then
      if sudocmd "get a list of running docker containers" docker ps | grep -q 'wg-access-server'; then
        return 0
      else
        return 1
      fi
  else
    return 1
  fi
}

get_nika_vpn_installed_path() {
  location=$(dirname $(sudo docker container inspect $1 --format '{{ index .Config.Labels "com.docker.compose.project.config_files" }}'))
  if [ ! -d "$location" ]; then
    die "Error getting Nika-VPN installation path"
  fi
  echo $location
}

remove_old_installation() {
  info "Removing old installation..."
  location=$(get_nika_vpn_installed_path "wg-access-server")
  # Close ports
  nika_vpn_env_file="$location/$NIKA_VPN_ENV_FILENAME"

  # Close ports
  if [ -f $nika_vpn_env_file ]; then
    vpn_port=$(get_env_value "WG_WIREGUARD_PORT" $nika_vpn_env_file)
    admin_port=$(get_env_value "WG_PORT" $nika_vpn_env_file)
    wstunnel_port=$(get_env_value "WSTUNEL_WS_PORT" $nika_vpn_env_file)
    apt_close_ports $vpn_port $admin_port $wstunnel_port
  fi

  # Remove wstunnel service
  delete_wstunnel_service

  # Remove running containers
  if ! sudocmd "stop running docker service containers" docker compose -f "${location}/docker-compose.yml" down -v; then
    die "n\Error removing old docker container, please remove them manually, run \n'sudo docker compose -f ${location}/docker-compose.yml down -v"
  fi

  # Remove installation folder
 if ! sudocmd "remove old installation folder" rm -rf $location; then
    die "\nError removing old installation folder, please remove it manually, run \n'rm -rf $location'"
  fi
}

check_nika_vpn_installed() {
  if has_nika_vpn; then
    info "Nika VPN is already installed."

    if [ "$FORCE" = "true" ] ; then
      print_separator
      info "Forcing reinstallation."
      remove_old_installation
    else
      die "Run script with --force (or -f) option to reinstall. \n 'curl -sSL https://bit.ly/nika-vpn-install | sh -s - -f'"
    fi
  else
    info "Nika VPN is not installed."
  fi
}

validate_params() {
  subnet_prefix=$(get_subnet_prefix "$SERVICES_SUBNET")
  unbound_prefix=$(get_subnet_prefix "$UNBOUND_LOCAL_IP")
  pihole_prefix=$(get_subnet_prefix "$PI_HOLE_LOCAL_IP")
  wg_prefix=$(get_subnet_prefix "$WG_LOCAL_IP")
  wg_subnet_prefix=$(get_subnet_prefix "$WG_VPN_CIDR")

  if [ "$subnet_prefix" != "$unbound_prefix" ]; then
    die "The specified local address ${UNBOUND_LOCAL_IP} does not belong to the specified network ${SERVICES_SUBNET}"
  fi

  if [ "$subnet_prefix" != "$pihole_prefix" ]; then
    die "The specified local address ${PI_HOLE_LOCAL_IP} does not belong to the specified network ${SERVICES_SUBNET}"
  fi

  if [ "$subnet_prefix" != "$wg_prefix" ]; then
    die "The specified local address ${WG_LOCAL_IP} does not belong to the specified network ${SERVICES_SUBNET}"
  fi

  if [ "$subnet_prefix" = "$wg_subnet_prefix" ]; then
    die "Subnet ranges for Nika-VPN services and VPN users must not match"
  fi

  if [ "$WG_PORT" = "$WG_WIREGUARD_PORT" ]; then
    die "The port for connecting to the VPN and the port for administering the VPN must not be the same."
  fi

  if [ "$WSTUNNEL_ENABLED" = "true" ]; then
    if [ "$WSTUNEL_WS_PORT" = "$WG_PORT" ]; then
      die "The port for tunneling VPN traffic via web socket must not be the same as the port for VPN administration"
    fi
    if [ "$WSTUNEL_WS_PORT" = "$WG_WIREGUARD_PORT" ]; then
      die "The port for tunneling VPN traffic via web socket must not be the same as the port for connecting to the VPN"
    fi
  fi
}

trap cleanup_temp_dir EXIT

make_temp_dir

if echo $@ | grep -qw -e "\-\-help" -e "\-h"; then
  show_help
  exit 0
fi

while [ $# -gt 0 ]; do
  case "$1" in
    -q|--quiet)
      # This tries its best to reduce output by suppressing the script's own
      # messages and passing "quiet" arguments to tools that support them.
      QUIET="true"
      shift
      ;;
    -f|--force)
      FORCE="true"
      shift
      ;;
    -d|--dest)
      DEST="$2"
      shift 2
      ;;
    -tz|--time-zone)
      if set_timezone "$2" ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -ss|--services-subnet)
      if set_service_subnet "$2" ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -ul|--unbound-local-ip)
      if set_unbound_local_ip "$2" ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -pl|--pihole-local-ip)
      if set_pihole_local_ip "$2" ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -pp|--pihole-password)
      PI_HOLE_PASSWORD="$2"
      shift 2
      ;;
    -wl|--wg-local-ip)
      if set_wg_local_ip "$2" ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -wpk|--wg-private-key)
      WG_WIREGUARD_PRIVATE_KEY="$2"
      shift 2
      ;;
    -au|--admin-username)
      WG_ADMIN_USERNAME="$2"
      shift 2
      ;;
    -ap|--admin-password)
      WG_ADMIN_PASSWORD="$2"
      shift 2
      ;;
    -pv|--port-vpn)
      if set_vpn_port $2 ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -pa|--port-admin)
      if set_admin_port $2 ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -ll|--log-level)
      if set_log_level $2 ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -ws|--wg-storage)
      WG_STORAGE="$2"
      shift 2
      ;;
    -dm|--disable-metadata)
      WG_DISABLE_METADATA="true"
      shift
      ;;
    -сf|--config-filename)
      WG_FILENAME="$2"
      shift 2
      ;;
    -wi|--wg-interface)
      WG_WIREGUARD_INTERFACE="$2"
      shift 2
      ;;
    -vc|--vpn-cidr)
      if set_vpn_cidr "$2" ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -vc6|--vpn-cidrv6)
      WG_VPN_CIDRV6="$2"
      shift 2
      ;;
    -nd|--nat-disabled)
      WG_IPV4_NAT_ENABLED="false"
      shift
      ;;
    -nd6|--nat-enable-v6)
      WG_IPV6_NAT_ENABLED="true"
      shift
      ;;
    -ai|--allowed-ips)
      WG_VPN_ALLOWED_IPS="$2"
      shift 2
      ;;
    -dd|--dns-disabled)
      WG_DNS_ENABLED="false"
      shift
      ;;
    -dn|--dns-domain)
      if set_dns_domain "$2" ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -eh|--external-host)
      if set_external_host "$2" ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -ci|--client-isolation)
      WG_VPN_CLIENT_ISOLATION="true"
      shift
      ;;
    --wf|--without_firewall)
      WITH_FIREWALL="false"
      shift
      ;;
    -pw|--port-web-socket)
      if set_web_socket_port $2 ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -wd|--web-socket-disabled)
      WSTUNNEL_ENABLED="false"
      shift
      ;;
    *)
      echo "Invalid argument: $1" >&2
      echo "Run '$0 --help' for more information." >&2
      exit 1
      ;;
  esac
done

validate_params
check_nika_vpn_installed
do_os
