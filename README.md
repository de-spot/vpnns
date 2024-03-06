# vpnns
Linux network namespace configuration to use with OpenVPN client.

```text
Usage:
    vpnns.sh [ OPTIONS... ]
Create and configure network namespace for isolated environment connected via OpenVPN to remote network.

  OPTIONS:
    --debug         set -x to show all lines executed by bash after parameters were parsed
    --verbose       show some additional information
    --help          hmmmmm...
    --ns-up         create network namespace with name nns79a0fbc4; name can be changed in script body, no other customizations so far
    --ns-down       delete network namespace with name nns79a0fbc4; also terminates all applications that uses this namespace (careful!)
    --info          display information about namespace, if created
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

VPN configuration should have name "yourvpncfg.ovpn"; set it using variable VPNNAME.
Configuration will be searched in "/home/username/openvpn" and then in "/etc/openvpn". Can be overridden by variable VPNCFGDIR

Generic usage sequence:
   1. VPNNAME=yourvpncfg vpnns.sh --ns-up
   2. VPNNAME=yourvpncfg vpnns.sh --vpn-up
   3. VPNNAME=yourvpncfg vpnns.sh --exec cmd with params, e.g. ip route show
   4. VPNNAME=yourvpncfg vpnns.sh --vpn-down
   5. VPNNAME=yourvpncfg vpnns.sh --ns-down
or
   1. VPNNAME=yourvpncfg vpnns.sh --all-up
   2. VPNNAME=yourvpncfg vpnns.sh --exec cmd with params, e.g. ip route show
   3. VPNNAME=yourvpncfg vpnns.sh --all-down
```
