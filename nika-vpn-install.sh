#!/bin/bash
#
# https://github.com/pprometey/nika-vpn
#
# Copyright (c) 2018 Alexei Chernyavski. Released under the MIT License.

# Checking Prerequisites
if [[ "$EUID" -ne 0 ]]; then
    echo "Sorry, you need to run this as root (sudo bash nika-vpn-install.sh)"
    exit 1
fi

# Detect OS
if [[ -e /etc/debian_version ]]; then
    DISTRO=$( lsb_release -is )
else
    echo "Your distribution is not supported (yet)"
    exit 1
fi

if [[ "$( systemd-detect-virt )" == "openvz" ]]; then
    echo "OpenVZ virtualization is not supported"
    exit 1
fi

run_path="$(readlink -f $0 | xargs dirname)"
root_path=$HOME
restore_file="$root_path/.nika-vpn-restore"
restore_timezone="restore_timezone"
restore_wireguard_port="restore_wireguard_port"
restore_wireguard_admin_port="restore_wireguard_admin_port"

create_restore_file() {
cat << EOF > $restore_file
$restore_timezone=
$restore_wireguard_port=
$restore_wireguard_admin_port=
EOF
}

function get_resore_value() {
    grep "${1}" ${restore_file} | cut -d'=' -f2
}

first_run() {
    echo
    echo 'Installing required programs and dependencies'
    echo
    echo "----- Enable auto-update OS ----- "
    # Update packages
    sudo apt update && sudo apt upgrade -y

    # Install unattended-upgrades
    sudo apt install -y unattended-upgrades

    # Configure unattended-upgrades
    sudo dpkg-reconfigure -pmedium unattended-upgrades

    echo
    echo "----- Install dependencies ----- "
    sudo apt install -y \
        ca-certificates \
        curl \
        gnupg \
        lsb-release \
        software-properties-common \
        git

    echo
    echo "----- Install Docker ----- "
    # Install docker 
    ## Add Docker's official GPG key
    if [[ ! -e /usr/share/keyrings/docker-archive-keyring.gpg ]]; then 
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    fi

    ## Add Docker's repository
    echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    ## Update the apt package index
    sudo apt update

    ## Install the latest version of Docker CE
    sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

    create_restore_file
}

get_wireguard_private_key() {
    wireguard_private_key=$(docker run -it --rm ghcr.io/freifunkmuc/wg-access-server wg genkey)
}

default_time_zone="Etc/UTC";
get_time_zone() {
    echo
    echo "Enter the time zone of the server"
    echo "See the list of zones here: https://en.wikipedia.org/wiki/List_of_tz_database_time_zones"
    read -p "Time zone [$default_time_zone]: " time_zone
    until [[ -z "$time_zone" || "$time_zone" =~ ^[a-zA-Z/]+$ ]]; do
        echo "$time_zone: invalid time zone."
        read -p "Time zone: " time_zone
    done
    [[ -z "$time_zone" ]] && time_zone=$default_time_zone
}

get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
   <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" \
   || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")

set_local_ip() {
    local_subnet_prefix=${1%.*}
    unbound_local_ip=$local_subnet_prefix.254
    pihole_local_ip=$local_subnet_prefix.253
    wireguard_local_ip=$local_subnet_prefix.252
}

default_local_subnet="10.254.254.0/24"
get_local_subnet() {
    echo
    echo "Enter internal subnet for the wireguard and server and peers"
    read -p "Local subnet [$default_local_subnet]: " local_subnet
    until [[ -z "$local_subnet" || "$local_subnet" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}$ ]]; do
        echo "$local_subnet: invalid subnet."
        read -p "Local subnet: " local_subnet
    done
    [[ -z "$local_subnet" ]] && local_subnet=$default_local_subnet
    set_local_ip $local_subnet
}

get_pihole_password() {
    echo
    echo "Enter the password for the Phole Admin Panel (allowed empty)"
    read -p "Password: " pihole_password
}

default_wireguard_admin_name="admin@vpn"
get_wireguard_admin_name() {
    echo
    echo "Enter the administrator username of the wg-access-server"
    read -p "Administrator username [$default_wireguard_admin_name]: " wireguard_admin_name
    [[ -z "$wireguard_admin_name" ]] && wireguard_admin_name=$default_wireguard_admin_name
}

get_wireguard_admin_password(){
    echo
    echo "Enter the administrator password of the wg-access-server"
    read -p "Administrator password [randomly generated if empty]: " wireguard_admin_password
    [[ -z "$wireguard_admin_password" ]] && wireguard_admin_password=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1) \
        && echo "The administrator password is: $wireguard_admin_password"  
}

default_wireguard_port="51820"
get_wireguard_port() {
    echo
    echo "What port should WireGuard listen to?"
    read -p "Port [$default_wireguard_port]: " wireguard_port
    until [[ -z "$wireguard_port" || "$wireguard_port" =~ ^[0-9]+$ && "$wireguard_port" -le 65535 ]]; do
        echo "$wireguard_port: invalid port."
        read -p "Port: " wireguard_port
    done
    [[ -z "$wireguard_port" ]] && wireguard_port=$default_wireguard_port
}

default_wireguard_admin_port="8000"
get_wireguard_admin_port() {
    echo
    echo "Enter the port for Wireguard admin panel (http)"
    read -p "Port [$default_wireguard_admin_port]: " wireguard_admin_port
    until [[ -z "$wireguard_admin_port" || "$wireguard_admin_port" =~ ^[0-9]+$ && "$wireguard_admin_port" -le 65535 ]]; do
        echo "$wireguard_admin_port: invalid port."
        read -p "Port: " wireguard_admin_port
    done
    [[ -z "$wireguard_admin_port" ]] && wireguard_admin_port=$default_wireguard_admin_port
}

default_wireguard_clients_subnet="10.254.253.0/24"
get_wireguard_client_subnet() {
    echo
    echo "Enter internal subnet for the Wireguard VPN clients"
    read -p "Wiregurad clients local subnet [$default_wireguard_clients_subnet]: " wireguard_clients_subnet
    until [[ -z "$wireguard_clients_subnet" || "$wireguard_clients_subnet" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}$ ]]; do
        echo "$wireguard_clients_subnet: invalid subnet."
        read -p "Wiregurad clients local subnet: " wireguard_clients_subnet
    done
    [[ -z "$wireguard_clients_subnet" ]] && wireguard_clients_subnet=$default_wireguard_clients_subnet
}

default_wireguard_allowed_ips="0.0.0.0/0,::/0"
get_wireguard_allowed_ips() {
    echo
    echo "Allowed IPs that clients may route through this VPN"
    read -p "Allowed IPs [$default_wireguard_allowed_ips]: " wireguard_allowed_ips
    until [[ -z "$wireguard_allowed_ips" ]]; do
        echo "$wireguard_allowed_ips: invalid allowed IPs."
        read -p "Allowed IPs: " wireguard_clients_subnet
    done
    [[ -z "$wireguard_allowed_ips" ]] && wireguard_allowed_ips=$default_wireguard_allowed_ips
}

set_timezone_host() {
    echo
    echo "Set timezone"

    local local_restore_timezone="$restore_timezone=$(cat /etc/timezone | sed 's!/!\\/!g')"
    sed -i "s/$restore_timezone.*/$local_restore_timezone/" $restore_file

    sudo timedatectl set-timezone $time_zone
}

restore_timezone_host() {
    echo
    echo "Restore timezone"

    if [[ -e $restore_file ]]; then        
        local local_restore_timezone=$(get_resore_value $restore_timezone)
        sudo timedatectl set-timezone $local_restore_timezone
    fi
}

open_ports() {
    sudo iptables -A INPUT -p udp -m state --state NEW -m udp --dport $wireguard_port -j ACCEPT
    sudo iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport $wireguard_admin_port -j ACCEPT
   
    sudo netfilter-persistent save

    if [[ -e $restore_file ]]; then  
        local local_restore_wireguard_port="$restore_wireguard_port=$wireguard_port"
        sed -i "s/$restore_wireguard_port.*/$local_restore_wireguard_port/" $restore_file

        local local_restore_wireguard_admin_port="$restore_wireguard_admin_port=$wireguard_admin_port"
        sed -i "s/$restore_wireguard_admin_port.*/$local_restore_wireguard_admin_port/" $restore_file
    fi
}

close_ports() {  
    if [[ -e $restore_file ]]; then   
        local local_restore_wireguard_port=$(get_resore_value $restore_wireguard_port)
        local local_restore_wireguard_admin_port=$(get_resore_value $restore_wireguard_admin_port)

        sudo iptables -D INPUT -p udp -m state --state NEW -m udp --dport $local_restore_wireguard_port -j ACCEPT
        sudo iptables -D INPUT -p tcp -m state --state NEW -m tcp --dport $local_restore_wireguard_admin_port -j ACCEPT

        sudo netfilter-persistent save
    fi
}

path_to_nika_vpn="$root_path/nika-vpn"
result_file="$run_path/nika-vpn-memo"
remove_nika_vpn() {
    echo "Remove Nika VPN"

    cd $path_to_nika_vpn

    docker compose down -v

    cd $root_path 
    sudo rm -rf $path_to_nika_vpn

    close_ports
    restore_timezone_host

    if [[ -e $result_file ]]; then
      sudo rm -f $result_file
    fi
}

nika_vpn_repository="https://github.com/pprometey/nika-vpn.git"
clone_repository() {
    echo
    echo "Clone repository"

    if [ -d $path_to_nika_vpn ] || \
        [ $(docker ps | grep unbound) ] || \
        [ $(docker ps | grep pihole) ] || \
        [ $(docker ps | grep wg-access-server) ]; then
        echo
        echo "Nika-VPN is already installed, will be uninstalled"
        remove_nika_vpn
    fi

    git clone $nika_vpn_repository $path_to_nika_vpn && cd $path_to_nika_vpn
}

general_pre_installation() {
    if [[ ! -f $restore_file ]]; then
        echo 
        echo "This is the first run, you need to install the necessary dependencies"
        first_run
    fi

    echo 
    echo "----- Configure Nika-VPN ----- "

    clone_repository
    get_wireguard_private_key
}

set_default_values() {
    echo
    echo "Set default values"

    time_zone=$default_time_zone
    set_timezone_host
    local_subnet=$default_local_subnet
    set_local_ip $local_subnet
    pihole_password=""
    wireguard_clients_subnet=$default_wireguard_clients_subnet
    wireguard_allowed_ips=$default_wireguard_allowed_ips
}

path_to_env_file="$path_to_nika_vpn/.env"
create_env_file() {
    echo
    echo "Create environment docker file"

cat << EOF > $path_to_env_file
TZ=$time_zone

# local subnet varitables
LOCAL_SUBNET=$local_subnet

# unbound varitables
UNBOUND_LOCAL_IP=$unbound_local_ip

# pi-hole varitables 
PI_HOLE_LOCAL_IP=$pihole_local_ip
PI_HOLE_PASSWORD=$pihole_password

# wireguard varitables
WG_WIREGUARD_PRIVATE_KEY=$wireguard_private_key
WG_WIREGUARD_PORT=$wireguard_port
WG_VPN_CIDR=$wireguard_clients_subnet
WG_ADMIN_USERNAME=$wireguard_admin_name
WG_ADMIN_PASSWORD=$wireguard_admin_password
WG_LOCAL_IP=$wireguard_local_ip
WG_PORT=$wireguard_admin_port
WG_VPN_ALLOWED_IPS=$wireguard_allowed_ips
WG_DNS_UPSTREAM=$pihole_local_ip
WG_DNS_ENABLED=true
WG_LOG_LEVEL=info
WG_IPV6_NAT_ENABLED=false
WG_IPV4_NAT_ENABLED=true
WG_VPN_CIDRV6=0
EOF
}

print_result() {
cat << EOF > $result_file
****************************************************************
To create users and connect to VPN, go to the VPN server
administration panel at:

VPN control panel address: $get_public_ip:$wireguard_admin_port
Login: $wireguard_admin_name
Password: $wireguard_admin_password

----------------------------------------------------------------

To manage the Pi-hole ad blocker, after connecting via VPN,
go to the administration panel at:
Pi-hole dashboard: http://$pihole_local_ip/admin
Password: $pihole_password

----------------------------------------------------------------
 
You can always find this memo along the path: 
$result_file

****************************************************************
EOF

echo
echo
cat $result_file
}

general_post_installation() {
    create_env_file
    open_ports
    
    docker compose up -d
    docker compose ps
    
    echo
    print_result
    read -n1 -r -p "Press any key to continue..."
    echo
}

simple_installation() {
    echo "Simple installation"
    general_pre_installation

    get_wireguard_admin_name
    get_wireguard_admin_password

    get_wireguard_port
    get_wireguard_admin_port
   
    set_default_values

    general_post_installation
}

advanced_installation() {
    echo "Advanced installation"
    general_pre_installation

    get_time_zone
    set_timezone_host

    get_local_subnet

    get_pihole_password

    get_wireguard_admin_name
    get_wireguard_admin_password
    get_wireguard_port
    get_wireguard_admin_port
    get_wireguard_client_subnet
    get_wireguard_allowed_ips

    general_post_installation
}

clear
echo 'Welcome to this Nika-VPN installer!'
echo
echo "Select an option:"
echo "   1) Simple installation"
echo "   2) Advanced Installation"
echo "   3) Remove Nika-VPN"
echo "   4) Exit"
read -p "Option: " option
until [[ "$option" =~ ^[1-4]$ ]]; do
    echo "$option: invalid selection."
    read -p "Option: " option
done

case "$option" in
    1)
        simple_installation
        exit
    ;;
    2)
        advanced_installation
        exit
    ;;
    3)
        echo
        read -p "Confirm Nika-VPN removal? [y/N]: " remove
        until [[ "$remove" =~ ^[yYnN]*$ ]]; do
            echo "$remove: invalid selection."
            read -p "Confirm Nika-VPN removal? [y/N]: " remove
        done
        if [[ "$remove" =~ ^[yY]$ ]]; then
            remove_nika_vpn
            echo
            echo "Nika-VPN removed!"
        else
            echo
            echo "Nika-VPN removal aborted!"
        fi       
        exit
    ;;
    4)
        exit
    ;;
esac