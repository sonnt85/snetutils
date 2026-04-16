# snetutils

[![Go Reference](https://pkg.go.dev/badge/github.com/sonnt85/snetutils.svg)](https://pkg.go.dev/github.com/sonnt85/snetutils)

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

### Types

- `type DiscoveryInfo struct` — mDNS discovery result (host, port, info fields, IP addresses)
- `type DeviceCCCInfo struct` — CCC device discovery result (IP, port, device metadata)
- `type CamerasInfo struct` — ONVIF camera discovery result (device URL, XAddrs, scopes)

### Interface & Address
- `NetGetInterfaceIpv4Addr(iface) (string, error)` — interface IPv4
- `NetGetMac/NetGetMacs(iface...)` — interface MAC address(es)
- `NetGetCIDR/NetGetMask/NetGetDefaultGatewayOfIface(iface...)` — CIDR, mask, gateway
- `NetGetGatewayOfInterface/NetGetMetricOfInterface(iface, cidr)` — routing info
- `NetInterfaceIsUp(iface) (bool, error)` — interface state
- `NetGetStaticMac() string` — stable MAC (loopback/first-up interface)
- `IfaceGetAllName(noLocalhost...)` — list all interface names
- `IfaceIsPluged(ifacename string) bool` — check if network interface has a carrier (cable plugged in)
- `IfaceRestart(ifacename string) bool` — bring interface down then up
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
- `Ping(addr, iface string, timeouts ...time.Duration) (*net.IPAddr, time.Duration, error)` — ICMP ping (timeout is variadic, default 1s)
- `PingExternal(domain, iface string, timeout time.Duration) error` — system ping command
- `IsSsh/IsVnc(addr string, timeouts ...time.Duration)` — protocol detection
- `NetTCPClientSend(servAddr string, dataSend []byte, timeouts ...time.Duration) ([]byte, error)` — send data to a TCP server and receive a response

### Port
- `IsPortOpen(addr string, port int, proto string, timeouts ...time.Duration) bool` — check if a TCP/UDP port is open
- `IsPortAvailable(ip string, port int, timeouts ...time.Duration) bool` — check if a TCP port is available (not in use)
- `IsPortUsed(ip string, port int, timeouts ...time.Duration) bool` — check if a TCP port is in use
- `IsPortTcpAvailable/IsPortTcpUsed(ip string, port int, timeouts ...time.Duration) bool` — TCP-specific variants
- `IsPortUdpAvailable/IsPortUdpUsed(ip string, port int, timeouts ...time.Duration) bool` — UDP-specific variants
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
- `NetDiscoveryQuery(service string, timeout time.Duration, ifaces ...string) []*DiscoveryInfo` — mDNS browse, returns typed results
- `NetDiscoveryQueryCCC(service string, ifaces ...string) []DeviceCCCInfo` — discover CCC devices
- `OnvifSendProbe(ifaceName ...string) []string` — send WS-Discovery probe and return raw ONVIF device URLs
- `OnvifDiscovery(ifaces ...string) []CamerasInfo` — full ONVIF camera discovery with device metadata
- `MacFromIP(ip, ifaces...) (string, error)` — ARP lookup
- `NMConnectWifi(ifacename, ssid, password string) error` — connect to Wi-Fi via NetworkManager
- `NMCreateHostPost(ifacename, conname, ssid, password string) error` — create a Wi-Fi hotspot via NetworkManager

### Network Time
- `GetNetworkTime(ntpserver string, port int) (*time.Time, error)` — NTP query
- `TimeZoneGet() string` — get current system timezone name
- `TimeGetUTCFromInternet() string` — NTP then HTTP fallback
- `TimeUpdateFromInternet(tzone ...string) bool` — sync system clock
- `GetPublicIp() string` — retrieve public (WAN) IP address via external service

### REST API Builders
- `HABuildErrorCode(code, msg) HAErrorCode`
- `HABuildErrorResponse(errors, messages) *HAErrorResponse`
- `HABuildSuccessRespone(result, messages, resultInfo...) *HASuccessResponse`
- `HABuildErrorResponseStr/HABuildSuccessResponeStr(...)` — JSON string variants

## Author

**sonnt85** — [thanhson.rf@gmail.com](mailto:thanhson.rf@gmail.com)

## License

MIT License - see [LICENSE](LICENSE) for details.
