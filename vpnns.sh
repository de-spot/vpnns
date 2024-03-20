#!/bin/bash

# Origin: https://github.com/de-spot/vpnns/blob/master/vpnns.sh
#
# Quick and dirty(?) Linux network namespace configuration to use with OpenVPN (as client).
#
# Tested only for Debian 12. Should work on Ubuntu 20+
# See --help for more information
# Error handler will interrupt execution when started without user interaction or will ask user for continue after error.
#
# TODO: handle vpn configuration in command line (--vpn-config name-here) with default name = current user name
# TODO: add customization for namespace endpoints (variables VPN0* and VPN1*)
# TODO: check handling of multihost VPN servers (?)
# TODO: add firewall configuration
# MAYBE: implement support for socat redirection

set -u # exit on unbound variable
#set -e # exit on error
set -o pipefail
#set -x

SCRIPT=$(realpath "$0")
trap 'error ${LINENO}' ERR

verbose=${verbose:=""}

set +x
[[ -f `dirname $0`/_script-colors.sh ]] && . `dirname $0`/_script-colors.sh       # some decorations for messages
[[ -f `dirname $0`/../_script-colors.sh ]] && . `dirname $0`/../_script-colors.sh # some decorations for messages
# ... when no script-colors.sh found...
COLORINFOBLOCK=${COLORCYAN:=''}
COLORNONE=${COLORNONE:=''}
COLORINFO=${COLORINFO:=''}
COLORWARN=${COLORWARN:=''}
COLORERROR=${COLORERROR:=''}
COLORYELLOW=${COLORYELLOW:=''}

#set -x

for param in "$@"; do # special cases
    if [[ "${param}" == --version ]]; then
        echo vpnns.sh v0.99
        exit 0;
    fi
    if [[ "${param}" == --verbose ]]; then
        verbose=1
    fi
    if [[ "${param}" == --debug ]]; then
        set -x
    fi
done

if [[ $EUID -eq 0 ]]; then
    echo -e "${COLORERROR}Please do not run this script as root. Sudo used inside for safety.${COLORNONE}"
    exit 1
fi

VPNNAME=${VPNNAME:=""} # VPN Provider Name (config, etc)
# Try to find configuration file vpnns.conf if VPNNAME is not set
[[ $verbose ]] && echo "VPNNAME before config lookups: $VPNNAME"
cfgfound=""
findconfig(){
    [[ $verbose ]] && echo -e "${COLORINFO}findconfig: now in directory: $1${COLORNONE}"
    local fname="$1/vpnns.conf"
    if [ -f "$fname" ]; then
        [[ $verbose ]] && echo "findconfig: found vpnns.conf in $1 (full name: $fname)"
        source "$fname"
        cfgfound="yes"
    fi
}

# Check per-directory configuration for VPNNAME if VPNNAME has not been set
# Traverse from 'currentdir' to 'topmostdir' calling 'callback-function'
# topmostdir MUST exists!
#
# Args: topmostdir currentdir callback-function
uptodir(){
    if [ -z "$1" -o -z "$2" -o -z "$3" ]; then
        echo >&2 "uptodir() requires three arguments"
        exit 1
    fi
    local TOPMOST=$1
    local CURR="$2"
    local CALLBACK="$3"
    # Handle current dir
    "$CALLBACK" "$CURR"
    if [ "$cfgfound" = "yes" ]; then
        return
    fi
    if [ "$CURR" == "$TOPMOST" ]; then
        return
    fi
    local PARENT=`dirname "$CURR"`
    uptodir "$TOPMOST" "$PARENT" "$CALLBACK"
}
if [ -z "${VPNNAME}" ]; then
    [[ $verbose ]] && echo "Trying to find configuration file vpnns.conf up to home dir and in ~/.config..."
    uptodir "$HOME" "$PWD" "findconfig"
fi

if [ -z "${VPNNAME}" -a -f "$HOME/.config/vpnns.conf" ]; then
    [[ $verbose ]] && echo -e "${COLORINFO}found vpnns.conf in ${HOME}/.config/"
    cat "$HOME/.config/vpnns.conf"
    source "$HOME/.config/vpnns.conf"
fi

[[ $verbose ]] && echo "VPNNAME after config lookups: $VPNNAME"

ARGS=("$@")
EXECASUSER=${RUNASUSER:=$USER}
VPNNS=${VPNNS:=""}    # Name of Network Name Space - use given or generate later
VPNNAME=${VPNNAME:=vpnna8me-has-not-been-set} # VPN Provider Name (config, etc)
ROUTE_MARKER=${ROUTE_MARKER:=""} # Will be generated if not given
VPN0=VPN0ns
VPN0IP=10.10.10.1
VPN0NET=10.10.10.0/24
VPN1=VPN1ns
VPN1IP=10.10.10.2
VPN1NET=10.10.10.0/24
VPN1GW=10.10.10.254
SYSTEM_VPNCFGDIR="/etc/openvpn"
USER_VPNCFGDIR="/home/$USER/openvpn"
VPNCFGDIR=${VPNCFGDIR:=$USER_VPNCFGDIR}
VPNPIDDIR=/var/run
VPNCFG=${VPNNAME}.ovpn
VPNPID=${VPNPIDDIR}/${VPNNAME}.pid

DETECTEDEXTIF=$(ip route show to 0/0| cut -d' ' -f 5)
[[ $verbose ]] && echo -e "${COLORINFO}Guessed external interface: ${DETECTEDEXTIF}${COLORNONE}"
EXTIF=${EXTIF:=""}
if [ -z "${EXTIF}" ]; then
    [[ $verbose ]] && echo -e "${COLORINFO}No external interface forced, will use guessed one.${COLORNONE}"
fi
EXTIF=${EXTIF:=$DETECTEDEXTIF} # "Outgoing" interface

NS_EXEC="echo -e ${COLORERROR}Something wrong in script happened...${COLORNONE}; exit 1;" #Will be overridden

#TODO: extract multiple IP addresses of VPN servers from configuration file
#TODO: Use something like:
# grep "^remote " ${VPNCFGDIR}/${VPNCFG}|sed -e 's/^remote //g'|cut -d' ' -f 1|tr "\n" " "
REMOTE_VPN_IP=127.0.0.1 # Here will be IP address of VPN server (ip-tunnel via SSH) after config parsing
REMOTE_VPN_PORT=1194
error(){
     local linenum=$1
     local input="stub"
     echo -e "${COLORERROR:=''}Failure at line $linenum${COLORNONE:=''}"
     echo "Command/line/function failed:"
     cat -n $SCRIPT|head -n $linenum $SCRIPT|tail -n 1
     if [ -t 0 ]; then
         echo -e "${COLORINFO:=''}Terminal detected. Ask user for continue...${COLORNONE:=''}"
         while read -r -t 0; do read -r; done # clear stdin
         read -p "Continue script after error? [yN]: " input
         if [[ "x${input}" != "xy" ]] && [[ "x${input}" != "xY" ]]; then
             echo -e "${COLORWARN:=''}Exiting...${COLORNONE:=''}"
             exit 99
         fi
     else
         echo -e "${COLORERROR:=''}No input terminal detected (running in script/input is redirected), forcing exit due to error.${COLORNONE:=''}"
         exit 98;
     fi
}

print_help() {
    local BN=`basename $0`
    echo -e "${COLORINFO}Usage:${COLORNONE}\n    $BN [ OPTIONS... ]
\n${COLORINFO}Create and configure network namespace for isolated environment connected via OpenVPN to remote network.${COLORNONE}\n
  OPTIONS:
    --debug         set -x to show all lines executed by bash after parameters were parsed
    --verbose       show some additional information
    --help          hmmmmm...
    --ns-up         create network namespace with generated or provided name;
                    see notes below;
    --ns-down       delete created network namespace;
                    also terminates all applications that uses this namespace (careful!)
    --info          display information about namespace, if created
    --ps            display processes running inside network namespace
    --check         check how connection from within namespace and from host will look for external endpoints
    --check-config  check if kernel configuration meets requirements then exit
    --show-config   just show configuration
    --vpn-up        start OpenVPN client in background
    --vpn-down      terminates OpenVPN client
    --all-up        combine --ns-up, --vpn-up
    --all-down      combine --vpn-down --ns-down
    --exec cmd ...  execute command with parameters within created namespace; should be last argument;
                    will return exit code of 'cmd'
    --wrap cmd ...  combine --all-up --exec cmd ... (wait for termination) --all-down;
                    will return exit code of 'cmd'

${COLORINFO}Notes${COLORNONE}
VPN configuration expected to have name given via variable VPNNAME.
Configuration will be searched in \"${COLORYELLOW}/home/username/openvpn${COLORNONE}\" and then in \"${SYSTEM_VPNCFGDIR}\". Can be overridden by variable VPNCFGDIR
Routing markers will be autogenerated if not given via ROUTE_MARKER.
Namespace will be autogenerated out of ROUTE_MARKER value if not given via variable VPNNS.
\n${COLORINFO}Generic usage sequence:${COLORNONE}
   1. VPNNAME=yourvpncfg $BN --ns-up
   2. VPNNAME=yourvpncfg $BN --vpn-up
   3. VPNNAME=yourvpncfg $BN --exec cmd with params, e.g. ip route show
   4. VPNNAME=yourvpncfg $BN --vpn-down
   5. VPNNAME=yourvpncfg $BN --ns-down
or
   1. VPNNAME=yourvpncfg $BN --all-up
   2. VPNNAME=yourvpncfg $BN --exec cmd with params, e.g. ip route show
   3. VPNNAME=yourvpncfg $BN --all-down
or
   1. VPNNAME=yourvpncfg $BN --wrap cmd with params, e.g. ping -c 3 www.google.com
"
}

show_config() {
    echo -e "${COLORINFO}External interface: ${COLORYELLOW}${EXTIF}${COLORNONE}"
    echo -e "${COLORINFO}VPN configuration : ${COLORYELLOW}${VPNCFGDIR}/${VPNCFG}${COLORNONE}"
}

check_config() {
    local cntFailures=0
    if ! which socat &>/dev/null ; then
        echo -e "${COLORERROR}Unable to find socat. Please install it: 'sudo apt -y install socat'${COLORNONE}"
        ((cntFailures++))
    fi
    if [[ $(cat /proc/sys/net/ipv4/ip_forward) -ne 1 ]]; then
        echo -e "${COLORERROR}IP Forwarding should be enabled.${COLORNONE}"
        echo -e "${COLORINFO}Use 'sudo sysctl -w net.ipv4.ip_forward=1' to enable.${COLORNONE}"
        ((cntFailures++))
    fi
    if [[ -z "${VPNNAME}" ]]; then
        echo -e ${COLORERROR}VPN configuration has not been specified. Please set variable VPNNAME.${COLORNONE}
        ((cntFailures++))
    fi
    if [[ -f "${VPNCFGDIR}/${VPNCFG}" ]]; then
        # Set by user or in user home dir
        [[ $verbose ]] && echo -e "${COLORINFO}Found user-provided configuration: ${VPNCFGDIR}/${VPNCFG}${COLORNONE}"
    elif [[ -f "${SYSTEM_VPNCFGDIR}/${VPNCFG}" ]]; then
        VPNCFGDIR="${SYSTEM_VPNCFGDIR}"
        [[ $verbose ]] && echo -e "${COLORINFO}Using system's configuration: ${VPNCFGDIR}/${VPNCFG}${COLORNONE}"
    else
        echo -e "${COLORERROR}Unable to find VPN configuration file ${COLORYELLOW}${VPNCFG}${COLORERROR}.${COLORNONE}"
        echo -e "${COLORINFO}Tried locations: ${COLORYELLOW}${VPNCFGDIR}${COLORINFO}, ${COLORYELLOW}${SYSTEM_VPNCFGDIR}${COLORINFO}. Please set location using ${COLORYELLOW}VPNCFGDIR${COLORINFO} variable.${COLORNONE}"
        ((cntFailures++))
    fi
    if [[ cntFailures -eq 0 ]]; then
        # NOTE: Only first remote address will be used; no multiple addresses are handled so far
        REMOTE_VPN_IP=$(grep "^remote " ${VPNCFGDIR}/${VPNCFG}|head -n 1|sed -e 's/^remote //g'|cut -d' ' -f 1|tr -d "\n")
        REMOTE_VPN_PORT=$(grep "^remote " ${VPNCFGDIR}/${VPNCFG}|head -n 1|sed -e 's/^remote //g'|cut -d' ' -f 2|tr -d "\n")
        [[ $verbose ]] && echo -e "${COLORINFO}Remote VPN address/port: ${REMOTE_VPN_IP}/${REMOTE_VPN_PORT}${COLORNONE}"
        local isMarkerGenerated=0
        if [[ -z "${ROUTE_MARKER}" ]]; then
            ROUTE_MARKER=$(echo "${REMOTE_VPN_IP}/${REMOTE_VPN_PORT}"|md5sum|head -c 8)
            [[ $verbose ]] && echo -e "${COLORINFO}Mark value not given, generating... 0x${ROUTE_MARKER}${COLORNONE}"
            isMarkerGenerated=1
        else
            [[ $verbose ]] && echo -e "${COLORINFO}Mark value given: ${ROUTE_MARKER}${COLORNONE}"
        fi
        if [[ -z "${VPNNS}" ]]; then # Just use marker as NS name
            VPNNS="nns${ROUTE_MARKER}"
            [[ $verbose ]] && echo -e "${COLORINFO}Network Namespace name not given, using Mark: ${VPNNS}${COLORNONE}"
        else
            [[ $verbose ]] && echo -e "${COLORINFO}Network Namespace name given: ${VPNNS}${COLORNONE}"
        fi
        if [[ isMarkerGenerated -eq 1 ]]; then
            ROUTE_MARKER="0x${ROUTE_MARKER}"
        fi
        NS_EXEC="sudo ip netns exec $VPNNS"
        # sanity check for $VPNNS, as namespaces uses
        # file-based approach, the character '/' and the names "." and ".." are
        # forbidden. (Character '\0' and string "" are also forbidden, but
        # '\0' cannot be passed in an environment variable, and "" is
        # handled above.)
        case "$VPNNS" in
            */*|.|..)
                echo -e "${COLORERROR}Invalid network namespace name.${COLORNONE}" >&2
                ((cntFailures++))
                ;;
        esac
    fi

    if [[ cntFailures -ne 0 ]]; then
        echo -e "${COLORERROR}Please fix configration or provide required parameter.${COLORNONE}"
        exit 3
    fi
}
ns_ps() {
    if [[ ! -d "/etc/netns/${VPNNS}" ]]; then
        echo -e "${COLORERROR}Network namespace directory does not exist (/ect/netns/${VPNNS}/). Is namespace created?"
        exit 3
    fi
    PIDS=$(sudo ip netns pids $VPNNS|xargs -rd'\n')
    if [ -z "$PIDS" ]; then
        [[ $verbose ]] && echo -e "${COLORWARN}No pids found.${COLORNONE}"
    else
        [[ $verbose ]] && echo -e "${COLORYELLOW}Pids found:${COLORNONE} ${PIDS}"
        [[ $verbose ]] && echo -e "${COLORYELLOW}Processes inside \"$VPNNS\" \(detailed\):${COLORNONE}"
        ps uww --pid "$PIDS"
    fi
}
info() {
    echo -e ${COLORINFO}Existing network namespaces:${COLORNONE}
    sudo ip netns list
    if [[ -z "$(sudo ip netns list|grep ${VPNNS})" ]]; then
        echo -e "${COLORWARN}Network namespace ${COLORYELLOW}${VPNNS}${COLORWARN} not found, skipping further output.${COLORNONE}"
    else
        echo -e "${COLORINFO}Inside network namespace \"$VPNNS\":${COLORNONE}"
        [[ $verbose ]] && echo -e "${COLORINFO}Addresses:${COLORNONE}"
        $NS_EXEC ip addr sh
        [[ $verbose ]] && echo -e "${COLORINFO}Routes:${COLORNONE}"
        $NS_EXEC ip r sh
        [[ $verbose ]] && echo -e "${COLORINFO}iptables:${COLORNONE}"
        $NS_EXEC iptables -L --line-numbers
        [[ $verbose ]] && echo -e "${COLORINFO}Processes:${COLORNONE}"
        ns_ps;
    fi
    echo -e "${COLORINFO}Host info:${COLORNONE}"
    [[ $verbose ]] && echo -e "${COLORINFO}Addresses:${COLORNONE}"
    sudo ip addr sh
    [[ $verbose ]] && echo -e "${COLORINFO}Routes:${COLORNONE}"
    sudo ip r sh
    [[ $verbose ]] && echo -e "${COLORINFO}iptables:${COLORNONE}"
    sudo iptables -L --line-numbers
}

ns_up(){
    echo -e "vpnns: ${COLORINFO}Configuring namespace \"${VPNNS}\"...${COLORNONE}"
#    [[ $verbose ]] && echo Creating VPN namespace \"${VPNNS}\"...
#    return 0
    # Create separate namespace for programs that will be routed over VPN
    sudo ip netns add $VPNNS                            # create named namespace

    $NS_EXEC ip addr add 127.0.0.1/8 dev lo             # create loopback inside namespace
    $NS_EXEC ip link set lo up                          # setting it up...







    sudo ip link add $VPN0 type veth peer name $VPN1      # add virtual interface to be used by netns for communication with external "world"
    sudo ip link set $VPN0 up                             # setting it up...
    sudo ip link set $VPN1 netns $VPNNS up                # создаем в netns интерфейс для общения во внешнем мире
                                                          # Assign IP addresses for both sides of veth
        sudo ip addr add $VPN0IP/24 dev $VPN0             # address for $VPN0
    $NS_EXEC ip addr add $VPN1IP/24 dev $VPN1             # address for $VPN1 inside netns
    $NS_EXEC ip link set dev $VPN1 mtu 1492               # reduce fragmentation
    $NS_EXEC ip route add default via $VPN0IP dev $VPN1
    # Add routing from netns to external; TODO: handle multiple servers (?)
###    $NS_EXEC ip route add ${REMOTE_VPN_IP} via $VPN1IP dev $VPN1 # add route to VPN server (ip tunnel via SSH)
#    $NS_EXEC ip route add default via $VPN1GW dev $VPN1   # add non-existing (in our) network address as gw; OpenVPN will replace it to own addr; will not work without it
#    $NS_EXEC ip route add default via $VPN1IP dev $VPN1   # add non-existing (in our) network address as gw; OpenVPN will replace it to own addr; will not work without it
#    $NS_EXEC ip route add default dev $VPN1 # add non-existing (in our) network address as gw; OpenVPN will replace it to own addr; will not work without it
                                                          # Configure resolvers
    sudo mkdir -p /etc/netns/${VPNNS}
    # ||(echo -e "${COLORERROR}Failed to create resolv.conf${COLORNONE}"; exit 1)
    cat <<EOF | sudo tee /etc/netns/${VPNNS}/resolv.conf > /dev/null
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF

#    sudo iptables -A INPUT ! -i $VPN0 -s $VPN0NET -j DROP # prevent spoofing
    sudo iptables -t nat -A POSTROUTING -s $VPN0NET -o $EXTIF -m mark --mark ${ROUTE_MARKER} -j MASQUERADE # configure NAT
    sudo iptables -t mangle -A PREROUTING -i $VPN0 -j MARK --set-xmark ${ROUTE_MARKER}/0xffffffff
    # TODO: create firewall rules for specific VPN config;
    # $NS_EXEC iptables-restore < /etc/iptables/iptables-${NS_NAME}.rules

    [[ $verbose ]] && echo -e "${COLORINFO}NS Configured. Checking if it is functioning...${COLORNONE}"
    $NS_EXEC sudo -u $EXECASUSER ping -c 3 www.google.com 2>&1 > /dev/null
    local RET=$? # save result
    if [[ $RET -eq 0 ]]; then
        [[ $verbose ]] && echo -e "${COLORINFO}Network namespace is up.${COLORNONE}"
    else
        echo -e "vpnns: ${COLORERROR}Network namespace failed routing...${COLORNONE}"
    fi
    return $RET # return ping result
}
ns_down() {
    echo -e "vpnns: ${COLORINFO}Shutting down namespace \"$VPNNS\"...${COLORNONE}"
    sudo ip netns pids $VPNNS | xargs -rd'\n' sudo kill
    echo -e "vpnns: ${COLORINFO}Waiting for termination...${COLORNONE}"
    #TODO: wait for termination...
#    sleep 1
    [[ $verbose ]] && echo -e "vpnns: ${COLORINFO}Deleting iptables...${COLORNONE}"
#    sudo iptables -D INPUT ! -i $VPN0 -s $VPN0NET -j DROP
    sudo iptables -t nat -D POSTROUTING -s $VPN0NET -o $EXTIF -m mark --mark ${ROUTE_MARKER} -j MASQUERADE
    sudo iptables -t mangle -D PREROUTING -i $VPN0 -j MARK --set-xmark ${ROUTE_MARKER}/0xffffffff

    [[ $verbose ]] && echo -e "vpnns: ${COLORINFO}Deleting namespace...${COLORNONE}"
    sudo rm -rf /etc/netns/$VPNNS

    sudo ip link del $VPN0
    sudo ip netns delete $VPNNS
    echo -e "vpnns: ${COLORINFO}Namespace has been shut down.${COLORNONE}"
}

check() {
    [[ $verbose ]] && echo "Existing netns\'es:"
    [[ $verbose ]] && sudo ip netns list
    # Check if we have OpenVPN inside network namespace
    [[ $verbose ]] && echo "Checking using namespace \"$VPNNS\" network:"
    $NS_EXEC sudo -u $EXECASUSER curl http://ifconfig.me/all.json
    echo ""
    [[ $verbose ]] && echo "Checking using host network:"
    sudo -u $EXECASUSER curl http://ifconfig.me/all.json
    echo ""
}
EXECRETVAL=0
exec_in_ns(){
    [[ $verbose ]] && echo -e "${COLORINFO}Running application inside ${COLORYELLOW}\"${VPNNS}\"${COLORINFO} as ${COLORYELLOW}${USERNAME}${COLORNONE}"
    [[ $verbose ]] && echo -e "${COLORINFO}Executing: ${COLORYELLOW}${ARGS[@]}${COLORNONE}"
    [[ $verbose ]] && echo -e "ARGS: ${ARGS[@]}"
#    [[ $verbose ]] && echo -e "${COLORINFO}Executing line: ${COLORYELLOW}${NS_EXEC} sudo -u $EXECASUSER ${ARGS[@]}${COLORNONE}"
    echo -e "vpnns: ${COLORINFO}Executing line: ${COLORYELLOW}${NS_EXEC} sudo -u $EXECASUSER ${ARGS[@]}${COLORNONE}"
    trap - ERR # Disable handler
    $NS_EXEC sudo -u $EXECASUSER "${ARGS[@]}"
    local RET=$?
    if [[ $RET -ne 0 ]]; then
          echo -e "vpnns: ${COLORERROR}Command execution result: ${RET}${COLORNONE}"
    fi
    EXECRETVAL=$RET  #Store to use as return value from script
    trap 'error ${LINENO}' ERR # Reinstall handler
    return 0
}

#TODO: redirection is not complete yet
vpn_up_with_redir() {
    [[ $verbose ]] && echo Starting port redirector to remote side OpenVPN
#    SOCATLOCK=/tmp/socat_${VPNNS}.lock #TODO: incomplete
    # SSH port forwarding bound to localhost, so we need some help
    if [ -f $SOCATLOCK ]; then
        echo -e ${COLORWARN}Port forwarder \(socat\) already started, not starting again. Kill file $SOCATLOCK manually.${COLORNONE}
    else
        socat -L $SOCATLOCK tcp-l:${REMOTE_VPN_PORT},bind=${REMOTE_VPN_IP},fork,range=$VPN0NET tcp:127.0.0.1:${REMOTE_VPN_PORT} &
        PFPID=$!
        RSLT=$?
        sleep 1
        echo PFPID=$PFPID RSLT=$?
        echo Socat started, pid: 
        cat $SOCATLOCK
    fi
#    if (socat tcp-l:${REMOTE_VPN_PORT},bind=${REMOTE_VPN_IP},fork,range=$VPN0NET tcp:127.0.0.1:${REMOTE_VPN_PORT} &); then
#        PFPID=$!
#        echo -e ${COLORINFO}Port forwarder started, pid=$PFPID${COLORNONE}
#    else
#        echo -e ${COLORERROR}Failed to start port forwarder${COLORNONE}
#    fi
    jobs
    [[ $verbose ]] && echo Starting OpenVPN inside \"$VPNNS\" using ${VPNCFGDIR}/${VPNCFG}; pid file: ${VPNPID}
    $NS_EXEC /usr/sbin/openvpn --daemon --writepid ${VPNPID} --cd ${VPNCFGDIR}/ --config ${VPNCFG} || echo -e ${COLORERROR}Failed to start OpenVPN.${COLORNONE}
}
vpn_up() {
    [[ $verbose ]] && echo "Starting OpenVPN inside \"$VPNNS\" using ${VPNCFGDIR}/${VPNCFG}; pid file: ${VPNPID}"
    $NS_EXEC /usr/sbin/openvpn --daemon --writepid ${VPNPID} --cd ${VPNCFGDIR}/ --config ${VPNCFG} || echo -e ${COLORERROR}Failed to start OpenVPN.${COLORNONE}

    #Wait for tunnel interface appeared
    #while ! $NS_EXEC ip link show dev tun0 >/dev/null 2>&1; do sleep 0.5; done
}

vpn_down() {
    [[ $verbose ]] && echo -e ${COLORYELLOW}Processes inside \"$VPNNS\":${COLORNONE}
    PIDS=$(sudo ip netns pids $VPNNS|xargs -rd'\n')
    if [ -z "$PIDS" ]; then
        [[ $verbose ]] && echo -e ${COLORWARN}No pids found.${COLORNONE}
    else
        [[ $verbose ]] && echo -e ${COLORYELLOW}Pids found:${COLORNONE} $PIDS
        [[ $verbose ]] && echo -e ${COLORYELLOW}Processes inside \"$VPNNS\" \(detailed\):${COLORNONE}
        [[ $verbose ]] && ps uww --pid "$PIDS"
        [[ $verbose ]] && echo -e ${COLORYELLOW}Looking for OpenVPN inside \"$VPNNS\":${COLORNONE}
        [[ $verbose ]] && (ps uww --pid "$PIDS"|grep openvpn)
        [[ $verbose ]] && echo -e ${COLORYELLOW}Killing OpenVPN inside \"$VPNNS\":${COLORNONE}
        [[ $verbose ]] && ps --pid "$PIDS"|grep openvpn|sed -e 's/^[ \t]*//'|cut -d' ' -f1|xargs echo sudo kill
        ps --pid "$PIDS"|grep openvpn|sed -e 's/^[ \t]*//'|cut -d' ' -f1|xargs sudo kill
    fi
}

# Process and collect options and operations
for i in "${!ARGS[@]}"; do
    case "${ARGS[i]}" in
      '') # skip empty
          unset 'ARGS[i]'
          continue
          ;;
      --verbose)
          unset 'ARGS[i]'
          ;;
      --debug)
          unset 'ARGS[i]'
          ;;
      --all-up)
          OP1=all-up
          unset 'ARGS[i]'
          ;;
      --all-down)
          OP1=all-down
          unset 'ARGS[i]'
          ;;
      --ns-up)
          OP1=ns-up
          unset 'ARGS[i]'
          ;;
      --ns-down)
          OP1=ns-down
          unset 'ARGS[i]'
          ;;
      --check)
          OP1=check
          unset 'ARGS[i]'
          ;;
      --check-config)
          OP1=check-config
          unset 'ARGS[i]'
          ;;
      --show-config)
          OP1=show-config
          unset 'ARGS[i]'
          ;;
      --info)
          OP2=info
          unset 'ARGS[i]'
          ;;
      --vpn-up)
          OP1=vpn-up
          unset 'ARGS[i]'
          ;;
      --vpn-down)
          OP1=vpn-down
          unset 'ARGS[i]'
          ;;
      --ps)
          OP1=ps
          unset 'ARGS[i]'
          ;;
      --exec)
          OP1=exec
          unset 'ARGS[i]'
          ;;
      --wrap)
          OP1=wrap
          unset 'ARGS[i]'
          ;;
      --help)
          print_help;
          exit 0
          ;;
    esac
    [[ $verbose ]] && echo ARGS: ${ARGS[@]}
done

check_config; # force config check and populate context

[[ $verbose ]] && echo Final content of ARGS: ${ARGS[@]}

OP1=${OP1:=""}
OP2=${OP2:=""}
if [[ -z "$OP1" && -n "$OP2" ]]; then OP1=info; unset 'OP2'; fi
OP2=${OP2:=""}
[[ $verbose ]] && echo Final content of OP1: ${OP1}, OP2: ${OP2}

if [[ "$OP2" == "info" ]]; then
    echo -e "${COLORINFOBLOCK}########## --info before operation BEG${COLORNONE}"
    info;
    echo -e "${COLORINFOBLOCK}########## --info before operation END${COLORNONE}"
fi

case "$OP1" in
    info)
        info;
        ;;
    all-up)
        ns_up;
        vpn_up;
        ;;
    all-down)
        vpn_down;
        ns_down;
        ;;
    ns-up)
        ns_up;
        ;;
    ns-down)
        ns_down;
        ;;
    vpn-up)
        vpn_up;
        ;;
    vpn-down)
        vpn_down;
        ;;
    check)
        check;
        ;;
    check-config) # already checked
        ;;
    show-config)
        show_config;
        ;;
    ps)
        ns_ps;
        ;;
    exec)
        exec_in_ns $@;
        exit $EXECRETVAL
        ;;
    wrap)
        ns_up;
        vpn_up;
        exec_in_ns $@;
        vpn_down;
        ns_down;
        exit $EXECRETVAL
        ;;
    *)
        echo -e "${COLORERROR}No valid command given.${COLORNONE}\n"
        [[ $verbose ]] && echo -e "${COLORERROR}Unknown option: ${OP1}${COLORNONE}"
        print_help;
        exit 1
        ;;
esac
#check;
if [[ "$OP2" == "info" ]]; then
    echo -e "${COLORINFOBLOCK}########## --info after operation BEG${COLORNONE}"
    info;
    echo -e "${COLORINFOBLOCK}########## --info after operation END${COLORNONE}"
fi
