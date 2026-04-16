# snetutils

Network utility library for Go — interface management, connectivity checks, DNS resolution, port scanning, mDNS/ONVIF discovery, NTP, REST API response helpers, and more.

## Installation

```bash
go get github.com/sonnt85/snetutils
```

## Features

- Network interface information: IP, MAC, CIDR, gateway, metric, up/down state
- IPv4/IPv6 address helpers: parse CIDR, check public/private, increment, range check
- Connectivity checks: TCP ping, ICMP ping, online detection with retries
- DNS resolution with fallback and debug mode
- Route management: add/delete routes, set default gateway, DHCP renew, IP flush
- Port utilities: check if port is open/used/available (TCP/UDP), get free port(s)
- Service discovery: mDNS server/client, ONVIF camera discovery, CCC device discovery
- ARP: resolve MAC address from IP (`MacFromIP`)
- NetworkManager integration: connect to Wi-Fi, create hotspot
- NTP: get network time from NTP servers or HTTP headers
- HTTP client management: reset transport, flush connections
- REST API response builders (HA/Cloudflare-style JSON)

## Usage

```go
import "github.com/sonnt85/snetutils"

// Get interface IPv4 address
ip, _ := snetutils.NetGetInterfaceIpv4Addr("eth0")

// Check connectivity
online := snetutils.NetIsOnline(3, 2, "eth0") // 3 tries, 2s interval

// Wait until server is reachable
err := snetutils.NetWaitServerIsOnline("8.8.8.8:53", 30*time.Second, "eth0")

// DNS resolution
addrs, _ := snetutils.ResolverDomain("example.com")
ip4, _ := snetutils.ResolverDomain2Ip4("example.com")

// ICMP ping
ipaddr, rtt, err := snetutils.Ping("192.168.1.1", "eth0", 3*time.Second)

// Port check
open := snetutils.IsPortOpen("192.168.1.1", 22, "tcp")
free, _ := snetutils.GetFreeTcpPort()

// mDNS service announcement
srv, _ := snetutils.NetInitDiscoveryServer("192.168.1.100", 8080, "device-id", "_myapp._tcp", nil, "eth0")

// mDNS discovery
entries := snetutils.NetDiscoveryQuery("_myapp._tcp", 5*time.Second, "eth0")

// ONVIF camera discovery
cameras := snetutils.OnvifDiscovery("eth0")

// IP configuration
snetutils.IpConfig("192.168.1.100", "255.255.255.0", "192.168.1.1", "eth0")

// REST API response
resp := snetutils.HABuildSuccessResponeStr(result, nil)
```

## API

### Interface & Address
- `NetGetInterfaceIpv4Addr(iface) (string, error)` — interface IPv4
- `NetGetMac/NetGetMacs(iface...)` — interface MAC address(es)
- `NetGetCIDR/NetGetMask/NetGetDefaultGatewayOfIface(iface...)` — CIDR, mask, gateway
- `NetGetGatewayOfInterface/NetGetMetricOfInterface(iface, cidr)` — routing info
- `NetInterfaceIsUp(iface) (bool, error)` — interface state
- `NetGetStaticMac() string` — stable MAC (loopback/first-up interface)
- `IfaceGetAllName(noLocalhost...)` — list all interface names
- `GetOutboundIP/GetDefaultIface()` — outbound address and default interface
- `NetGetInterfaceInfo(infotype int, ifaces...)` — generic interface info by type constant

### IP Utilities
- `IpBetween(from, to, test net.IP) bool` — range check
- `IsPublicIP(ip net.IP) bool` — public IP check
- `IpIsPrivate(ip string) bool` — private range check
- `IpInc(ip net.IP)` — increment IP in-place
- `IpParserCIDR(cidr string) (mask, gateway, error)` — parse CIDR
- `NetIsIpv4(ip net.IP) bool` — v4 check
- `NetGetInameByIP(ip string) (string, error)` — reverse lookup interface name

### Connectivity
- `NetIsOnline/NetIsOnlineTcp/NetIsOnlinePing(tries, interval, ifaces...)` — connectivity test
- `NetWaitServerIsOnline(domain, timeout, ifaces...)` — block until reachable
- `ServerIsLive(domain, ifaces...)` — single connectivity check
- `Ping(addr, iface, timeout) (*net.IPAddr, time.Duration, error)` — ICMP ping
- `PingExternal(domain, iface, timeout) error` — system ping command
- `IsSsh/IsVnc(addr, timeout...)` — protocol detection

### Port
- `IsPortOpen/IsPortTcpAvailable/IsPortUdpAvailable(ip, port, timeouts...)` — availability checks
- `GetFreeTcpPort/GetFreeUdpPort() (int, error)` — allocate free port
- `GetFreePorts/GetFreeTcpPorts/GetFreeUdpPorts(count int)` — allocate multiple ports

### DNS & Routing
- `ResolverDomain(domain) ([]string, error)` — resolve to IP list
- `ResolverDomain2Ip4(domain) (string, error)` — resolve to first IPv4
- `NetRouteAdd/NetRouteDelete(iface, metric, cidr)` — manage routes
- `RouteDefault/GetIfaceRouteDefault()` — default route management
- `IpConfig/IpConfigAuto/IpFlush/IpDhcpRenew(...)` — IP configuration

### Discovery
- `NetInitDiscoveryServer(...)` — register mDNS service
- `NetDiscoveryQuery(service, timeout, ifaces...)` — mDNS browse
- `NetDiscoveryQueryCCC(service, ifaces...)` — discover CCC devices
- `OnvifDiscovery(ifaces...) []CamerasInfo` — ONVIF camera discovery
- `MacFromIP(ip, ifaces...) (string, error)` — ARP lookup

### Network Time
- `GetNetworkTime(ntpserver, port) (*time.Time, error)` — NTP query
- `TimeGetUTCFromInternet() string` — NTP then HTTP fallback
- `TimeUpdateFromInternet(tzone...) bool` — sync system clock

### REST API Builders
- `HABuildErrorCode(code, msg) HAErrorCode`
- `HABuildErrorResponse(errors, messages) *HAErrorResponse`
- `HABuildSuccessRespone(result, messages, resultInfo...) *HASuccessResponse`
- `HABuildErrorResponseStr/HABuildSuccessResponeStr(...)` — JSON string variants

## License

MIT License - see [LICENSE](LICENSE) for details.
