package snetutils

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IBM/netaddr"
	"github.com/beevik/etree"
	log "github.com/sirupsen/logrus"
	"github.com/sonnt85/gonetwork/arp"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/sonnt85/gonmmm"
	wsdiscovery "github.com/sonnt85/gonvif/ws-discovery"
	"github.com/sonnt85/gosutils/sexec"
	"github.com/sonnt85/gosutils/sregexp"
	"github.com/sonnt85/gosutils/sutils"
	"github.com/sonnt85/mdns"
)

const (
	IfaceIname int = iota
	IfaceMacddr
	IfaceCidr
	IfaceIp4
	IfaceIp6
	IfaceMask
)

type DeviceCCCInfo struct {
	From          string    `json:"from"`
	IP            string    `json:"ip"`
	Port          int       `json:"port"`
	Serial_number string    `json:"serial_number"`
	Device_id     string    `json:"device_id"`
	Extra         []string  `json:"more"`
	LastDiscovery time.Time `json:"-"`
	Version       string    `json:"Version"`
}

type DiscoveryInfo struct {
	Name string
	Host string
	Ip4  string
	Port int
	Info []string
}

type CamerasInfo struct {
	From             string    `json:"from"`
	IP               string    `json:"ip"`
	Name             string    `json:"name"`
	XADDR            string    `json:"xaddr"`
	UUID             string    `json:"uuid"`
	Hardware         string    `json:"hardware"`
	Location         string    `json:"location"`
	FirmwareVersion  string    `json:"firmware version"`
	LastConnectError time.Time `json:"last_error_time"`
	//	LastConnectError time.Time `json:",omitempty"`
}

func NetGetInterfaceIpv4Addr(interfaceName string) (addr string, err error) {
	var (
		ief      *net.Interface
		addrs    []net.Addr
		ipv4Addr net.IP
	)
	if ief, err = net.InterfaceByName(interfaceName); err != nil { // get interface
		return
	}
	if addrs, err = ief.Addrs(); err != nil { // get addresses
		return
	}
	for _, addr := range addrs { // get ipv4 address
		if ipv4Addr = addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
			break
		}
	}
	if ipv4Addr == nil {
		if len(addrs) != 0 {
			return "", fmt.Errorf(fmt.Sprintf("There isn't any ipv4 on interface %s\n", interfaceName))
		} else {
			return "", fmt.Errorf(fmt.Sprintf("There isn't any ip on interface %s\n", interfaceName))
		}
	}
	return ipv4Addr.String(), nil
}

func NetIfaceHasIpv4(interfaceName string) bool {
	if _, err := NetGetInterfaceIpv4Addr(interfaceName); err == nil {
		return true
	}
	return false
}

//func DetermineRouteInterface(serverAddr string) error {
//	var ip net.IP
//	if ip = net.ParseIP(serverAddr); ip == nil {
//		return fmt.Errorf("error as non-ip target %s is passed", serverAddr)
//	}
//
//	router, err := routing.New()
//	if err != nil {
//		return errors.Wrap(err, "error while creating routing object")
//	}
//
//	_, gatewayIP, preferredSrc, err := router.Route(ip)
//	if err != nil {
//		return errors.Wrapf(err, "error routing to ip: %s", serverAddr)
//	}
//
//	fmt.Printf("gatewayIP: %v preferredSrc: %v", gatewayIP, preferredSrc)
//	return nil
//}

var dnslist = []string{
	"1.1.1.1", "1.0.0.1", //clouflare
	//	"208.67.222.222", "208.67.220.220", //opendns server
	//	"8.8.8.8", "8.8.4.4", //google
	//	"8.26.56.26", "8.20.247.20", //comodo
	//	"9.9.9.9", "149.112.112.112", //quad9
	//	"64.6.64.6", "64.6.65.6"
} // verisign

func ResolverDomain(domain string, debugflag ...bool) (addrs []string, err error) {
	if addr := net.ParseIP(domain); addr != nil {
		return []string{domain}, nil
	}

	r := &net.Resolver{
		PreferGo: true,
		Dial:     nil,
	}

	for i := 0; i < len(dnslist); i++ {
		for _, pro := range []string{"udp", "tcp"} {
			r.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Millisecond * time.Duration(5000),
				}
				return d.DialContext(ctx, pro, dnslist[i]+":53")
			}

			if addrs, err = r.LookupHost(context.Background(), domain); err == nil {
				return
			}

			if len(debugflag) != 0 && debugflag[0] {
				fmt.Printf("\nCan not used dns server %s for finding %s\n", dnslist[i], domain)
			}
		}
	}
	return net.LookupHost(domain) //system lockup
}

func ResolverDomain2Ip4(domain string, debugflag ...bool) (addr string, err error) {
	if addrs, err := ResolverDomain(domain, debugflag...); err == nil {
		for _, v := range addrs {
			if strings.Contains(v, ".") {
				return v, nil
			}
		}
		return "", fmt.Errorf("there is not ipv4")
	} else {
		return "", err
	}
}

func NetCheckConectionToServer(domain string, ifacenames ...string) error {
	tcpAddr := &net.TCPAddr{}

	if len(ifacenames) != 0 {
		ip4add, err := NetGetInterfaceIpv4Addr(ifacenames[0])
		if err != nil || len(ip4add) == 0 {
			return err
		} else {
			tcpAddr.IP = net.ParseIP(ip4add)
		}
	} else {
		tcpAddr = nil
	}

	d := net.Dialer{LocalAddr: tcpAddr, Timeout: time.Millisecond * 2000}

	if !strings.Contains(domain, "://") {
		domain = "http://" + domain
	}
	u, err := url.Parse(domain)
	if err != nil {
		return err
	}
	port := "80"
	if u.Scheme == "https" {
		port = "443"
	}

	host := u.Host
	if thost, tport, _ := net.SplitHostPort(u.Host); len(thost) != 0 {
		port = tport
		host = thost
	}
	ip4, err := ResolverDomain2Ip4(host)
	if err != nil {
		//		log.Error(err, host)

		return err
	}
	if conn, err := d.Dial("tcp", ip4+":"+port); err != nil {
		//		log.Error(err)
		return err
	} else {
		conn.Close()
		return nil
	}
}

func ServerIsLive(domain string, ifacenames ...string) bool {
	tcpAddr := &net.TCPAddr{}

	if len(ifacenames) != 0 {
		ip4add, err := NetGetInterfaceIpv4Addr(ifacenames[0])
		if err != nil || len(ip4add) == 0 {
			return false
		} else {
			tcpAddr.IP = net.ParseIP(ip4add)
		}
	} else {
		tcpAddr = nil
	}

	d := net.Dialer{LocalAddr: tcpAddr, Timeout: time.Millisecond * 666}

	if !strings.Contains(domain, "://") {
		domain = "http://" + domain
	}
	u, err := url.Parse(domain)
	if err != nil {
		return false
	}
	port := "80"
	if u.Scheme == "https" {
		port = "443"
	}

	host := u.Host
	if thost, tport, _ := net.SplitHostPort(u.Host); len(thost) != 0 {
		port = tport
		host = thost
	}
	ip4, err := ResolverDomain2Ip4(host)
	if err != nil {
		//		log.Error(err, host)

		return false
	}
	if conn, err := d.Dial("tcp", ip4+":"+port); err != nil {
		//		log.Error(err)
		return false
	} else {
		conn.Close()
		return true
	}
}

func NetIsOnlineTcp(times, intervalsecs int, ifacenames ...string) bool {
	ifacename := ""
	if len(ifacenames) != 0 {
		ifacename = ifacenames[0]
	}
	//	timeout := time.Millisecond * 500
	//	if sutils.StringContainsI(ifacename, "ppp") {
	//		timeout = time.Millisecond * 3000
	//	}
	numDnsTest := len(dnslist)
	//	if numDnsTest >= 4 {
	//		numDnsTest = 4
	//	}
	ttk := time.NewTicker(time.Second * time.Duration(intervalsecs))
	for i1 := 0; i1 < times; i1++ {
		for i := 0; i < numDnsTest; i++ {
			//			log.Warn("Ping interface ", ifacename, dnslist[i])
			if ServerIsLive(dnslist[i], ifacename) {
				return true
			} else {
				//				log.Errorf("Error to use iface %s to test dns server: %s\n", ifacename, dnslist[i])
				continue
			}
		}
		if times > 1 {
			<-ttk.C
		}
	}
	return false
}

func NetIsOnlinePing(times, intervalsecs int, ifacenames ...string) bool {
	ifacename := ""
	if len(ifacenames) != 0 {
		ifacename = ifacenames[0]
	}
	timeout := time.Millisecond * 500
	//	if sutils.StringContainsI(ifacename, "ppp") {
	//		timeout = time.Millisecond * 3000
	//	}
	numDnsTest := len(dnslist)
	//	if numDnsTest >= 4 {
	//		numDnsTest = 4
	//	}
	ttk := time.NewTicker(time.Second * time.Duration(intervalsecs))
	for i1 := 0; i1 < times; i1++ {
		for i := 0; i < numDnsTest; i++ {
			//			log.Warn("Ping interface ", ifacename)
			if _, _, err := Ping(dnslist[i], ifacename, timeout); err != nil {
				//				if sutils.StringContainsI(ifacename, "ppp") {
				//				log.Errorf("Error to use iface %s to test dns server: %s\n%s\n", ifacename, dnslist[i], err.Error())
				//				}
				continue
			} else {
				//				log.Warnf("Use iface %s to test dns server: %s\n", ifacename, dnslist[i])
				return true
			}
		}
		if times > 1 {
			<-ttk.C
		}
	}
	return false
}

func PingExternal(domain, ifacename string, timeout time.Duration) error {
	cmd := fmt.Sprintf("ping -c 1 -I %s  %s", ifacename, domain)
	_, _, err := sexec.ExecCommandShell(cmd, timeout)
	return err
}

func NetIsOnlinePingExternal(times, intervalsecs int, ifacenames ...string) bool {
	ifacename := ""
	if len(ifacenames) != 0 {
		ifacename = ifacenames[0]
	}
	timeout := time.Millisecond * 1000
	//	if sutils.StringContainsI(ifacename, "ppp") {
	//		timeout = time.Millisecond * 3000
	//	}
	numDnsTest := len(dnslist)
	//	if numDnsTest >= 4 {
	//		numDnsTest = 4
	//	}
	ttk := time.NewTicker(time.Second * time.Duration(intervalsecs))
	for i1 := 0; i1 < times; i1++ {
		for i := 0; i < numDnsTest; i++ {
			//			log.Warn("Ping interface ", ifacename)
			if err := PingExternal(dnslist[i], ifacename, timeout); err != nil {
				//				if sutils.StringContainsI(ifacename, "ppp") {
				// log.Errorf("Error to use iface %s to test dns server: %s\n%s\n", ifacename, dnslist[i], err.Error())
				//				}
				continue
			} else {
				//				log.Warnf("Use iface %s to test dns server: %s\n", ifacename, dnslist[i])
				return true
			}
		}
		if times > 1 {
			<-ttk.C
		}
	}
	return false
}

func IfaceIsPluged(ifacename string) bool {
	if retbyte, err := ioutil.ReadFile(fmt.Sprintf("/sys/class/net/%s/carrier", ifacename)); err == nil {
		retstr := string(retbyte)
		retstr = sutils.StringTrimLeftRightNewlineSpace(retstr)
		if retstr == "1" {
			return true
		}
	}
	return false
}

func IfaceListHasInternet() (ifaces []string) {
	ifaces = make([]string, 0)
	interfaces, _ := net.Interfaces()
	for _, interf := range interfaces {
		iname := interf.Name
		if NetIsOnline(1, 1, iname) {
			ifaces = append(ifaces, iname)
			//			fmt.Printf("Iface %s is online \n", iname)
		}
		// else {
		//			fmt.Printf("Iface %s is offline \n", iname)
		//}
	}
	return
}

func IsOnline(times, intervalsecs int) bool {

	ttk := time.NewTicker(time.Second * time.Duration(intervalsecs))

	for i1 := 0; i1 < times; i1++ {
		if NetIsOnlineTcp(1, 1) || (len(GetPublicIp()) != 0) {
			return true
		}

		if times > 1 {
			<-ttk.C
		}
	}
	return false
}

func NetIsOnlineOld(times, intervalsecs int, ifacenames ...string) bool {

	ifacename := ""
	if len(ifacenames) != 0 && len(ifacenames[0]) != 0 {
		ifacename = ifacenames[0]
		if _, err := NetGetInterfaceIpv4Addr(ifacename); err != nil {
			return false
		}
	}
	numDnsTest := len(dnslist)
	ttk := time.NewTicker(time.Second * time.Duration(intervalsecs))

	for i := 0; i < times; i++ {
		for i := 0; i < numDnsTest; i++ {
			if len(ifacename) == 0 {
				// || (len(TimeGetUTCFromInternet()) != 0
				if NetIsOnlineTcp(1, 1) || (len(GetPublicIp()) != 0) {
					return true
				}
			} else {
				if NetIsOnlineTcp(1, 1, ifacename) {
					return true
				}
			}
		}

		if times > 1 {
			<-ttk.C
		}
	}
	return false
}

func NetIsOnline(times, intervalsecs int, ifacenames ...string) bool {
	ttk := time.NewTicker(time.Second * time.Duration(intervalsecs))
	for i1 := 0; i1 < times; i1++ {
		for i := 0; i < len(dnslist); i++ {
			cmd2run := fmt.Sprintf(`curl -m 5 %s`, dnslist[i])

			if len(ifacenames) != 0 {
				cmd2run = fmt.Sprintf(`curl -m 5  --interface %s %s`, ifacenames[0], dnslist[i])
			}
			if _, _, err := sexec.ExecCommandShell(cmd2run, time.Millisecond*2100); err == nil {
				return true
			}

			if times > 1 {
				<-ttk.C
			}
		}
	}
	return false
}

func HttpClientFlush() {
	http.DefaultClient.CloseIdleConnections()
}

func HttpClientNewTransPort() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 15 * time.Second,
			DualStack: true,
		}).DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 6 * time.Second,
		//		ExpectContinueTimeout:  1 * time.Second,
		MaxResponseHeaderBytes: 8192,
		ResponseHeaderTimeout:  time.Millisecond * 5000,
		DisableKeepAlives:      false,
	}
}

func HttpClientReset() {
	http.DefaultTransport = HttpClientNewTransPort()
}

func IfaceListAll() {
	interfaces, _ := net.Interfaces()

	for _, interf := range interfaces {
		maddrs, _ := interf.MulticastAddrs()
		addrs, _ := interf.Addrs()
		fmt.Printf("\n%+v\nMuticasaddrs%+v\nAddrs%+v\n", interf, maddrs, addrs)
	}
}

func IfaceGetAllName(noLocalhosts ...bool) (ifaces []string) {
	ifaces = []string{}
	noLocalhost := false
	if len(noLocalhosts) != 0 && noLocalhosts[0] {
		noLocalhost = true
	}
	interfaces, _ := net.Interfaces()
	for _, interf := range interfaces {
		if noLocalhost && ((interf.Flags & net.FlagLoopback) != 0) {
			continue
		}
		ifaces = append(ifaces, interf.Name)
	}
	return
}

var __ifaceLoopbackStaticList = []string{"lo"}

func NetGetStaticLoopbackName() (retstr string) {
	namekeys := []string{}

	interfaces, _ := net.Interfaces()
	for _, interf := range interfaces {
		if (interf.Flags & net.FlagLoopback) != 0 { //is loop back
			//			fmt.Println("\nnamekeys", interf.Name)
			//			inames[interf.Name] = interf.HardwareAddr.String()
			namekeys = append(namekeys, interf.Name)
		}
	}
	nm := len(namekeys)
	if nm != 0 {
		sort.Strings(namekeys)
		for i := 0; i < nm; i++ {
			name := namekeys[i]
			if sutils.SlideHasSubstringInStrings(__ifaceLoopbackStaticList, name) {
				return name
			}
		}
		return namekeys[0]
	}
	return ""
}

var __ifaceStaticList = []string{"eth", "wlan", "enp", "enx", "Ethernet", "en"}

func NetGetStaticMac() string {
	namekeys := []string{}
	imacs := map[string]string{}

	interfaces, _ := net.Interfaces()
	for _, interf := range interfaces {
		if (interf.Flags & net.FlagLoopback) == 0 { //cannot mac from loopback
			//			fmt.Println("\nnamekeys", interf.Name)
			imacs[interf.Name] = interf.HardwareAddr.String()
			namekeys = append(namekeys, interf.Name)
		}
	}
	nm := len(namekeys)
	//	fmt.Println("\nnum interface", nm)
	if nm != 0 {
		sort.Strings(namekeys)
		for i := 0; i < nm; i++ {
			mac := imacs[namekeys[i]]
			name := namekeys[i]
			if sutils.SlideHasSubstringInStrings(__ifaceStaticList, name) {
				//				fmt.Println("\nreturn interface", nm)
				return mac
			}
		}
		return imacs[namekeys[0]]
	} else {
		return ""
	}
}

func RouteTem(ifacename string, metrics ...int) (err error) {
	metric := 185
	if len(metrics) != 0 {
		metric = metrics[0]
	}
	if !NetIfaceHasIpv4(ifacename) {
		return fmt.Errorf("can not get ipv4 %s", ifacename)
	}
	gwip, _ := NetGetDefaultGatewayOfIface(ifacename)
	if _, stderr, err := sexec.ExecCommandShell(fmt.Sprintf(`iface=%s;
	        metric=%d;
			gwip=%s

			einfo=$(route -n | grep -e '^0.0.0.0' | grep ${iface} | sort -r -u -k2  |  head -n 1)
			egw=$(echo -n "${einfo}" | awk '{print $2}')

			for i in $(route -n | grep -e '^0.0.0.0' | grep ${iface} | awk '{print $5}'); do
			  ((i == 2021)) && exit 0
			  ((i <= metric)) && exit 0
			done
			[[ $gwip ]] && { [[ $gwip =~ "0.0.0.0" ]] || gw="gw ${gwip}"; } || gw=""
			[[ $gw ]] || {
			    [[ $egw ]] && { [[ $egw =~ "0.0.0.0" ]] || gw="gw ${egw}"; }
			}
			ip link show ${iface} | grep -Poe 'state\s+[^\s]+' | grep -ie UP -e UNKNOWN && \
			route add default metric ${metric} ${gw} dev ${iface}
			route -n | grep -e '^0.0.0.0' | grep ${iface} | awk '{print $5}' | grep -Pe "^${metric}$"`, ifacename, metric, gwip), time.Second*5); err == nil {
		return nil
	} else {
		return fmt.Errorf("%s", string(stderr))
	}
}

func RouteDel(ifacename string, metrics ...int) {

}

func GetIfaceRouteDefault() (ifacename string) {
	cmd := `route -n | grep -e '^0.0.0.0' | sort -u -k5 -g | head -n 1 | grep -Poe '[^\s]+$'`
	if stdou, _, err := sexec.ExecCommandShell(cmd, time.Millisecond*200); err != nil {
		return ""
	} else {
		return sutils.StringTrimLeftRightNewlineSpace(string(stdou))
	}
}

func RouteDefault(ifacename string, metrics ...int) (err error) {
	mt := 50
	if len(metrics) != 0 {
		mt = metrics[0]
	}

	cmd := fmt.Sprintf(`iface=%s
	        metric=%d

	        for i in $(route -n | grep -e '^0.0.0.0' | grep ${iface} | awk '{print $5}'); do
			  ((i <= metric)) && exit 0
			done

			deinfo=$(route -n | grep -e '^0.0.0.0' | grep -v ${iface} | sort -u -k5 -g | head -n 1)
			einfo=$(route -n | grep -e '^0.0.0.0' | grep ${iface} | sort -r -u -k2  |  head -n 1)
			gw=$(echo -n "${einfo}" | awk '{print $2}')
			gm=$(echo -n "${einfo}" | awk '{print $3}')
			mt=$(echo -n "${einfo}" | awk '{print $5}')

			dif=$(echo -n "${deinfo}" | awk '{print $8}')

			[[ $dif ]] && {

   			[[ ${dif} =~ ${iface} ]] || {
	   		   dgw=$(echo -n "${deinfo}" | awk '{print $2}')
		   	   dgm=$(echo -n "${deinfo}" | awk '{print $3}')
			   dmt=$(echo -n "${deinfo}" | awk '{print $5}')
			   [[ ${dgw} =~ '0.0.0.0' ]] && dgwconf="" || dgwconf="gw ${dgw}"
		       route del default metric ${dmt} dev ${dif}
			   route add default metric $((metric + 10)) ${dgwconf} dev ${dif}
			}

			}

			{ [[ ${gw} =~ '0.0.0.0' ]] || ! [[ ${gw} ]]; } && gwconf="" || gwconf="gw ${gw}"
			[[ ${mt} ]] && route del default metric ${mt} dev ${iface}
			ip link set dev ${iface}  up
			route add default metric ${metric} ${gwconf} dev ${iface}
			echo "Gateway default ${gwconf}"
			route -n | grep -e '^0.0.0.0' | grep -e ${iface} | awk '{print $5}' | grep -Pe "^${metric}$"`, ifacename, mt)
	if _, stderr, err := sexec.ExecCommandShell(cmd, time.Millisecond*2000); err != nil {
		//		log.Printf("\nRoute command\n%s", cmd)
		//		log.Printf("\nError output\n%s", string(stderr))
		//		log.Printf("\nStdout\n%s", string(stdou))
		return fmt.Errorf("%s", string(stderr))
	} else {
		// log.Warnf("RouteDefault cmd %s\n%s\n\nstdout:\n%s\nstderr:\n%s\n", cmd, ifacename, string(stdou), string(stderr))
		return nil
	}
}

func GetPublicIp() string {
	serversList := []string{
		"https://icanhazip.com",
		"http://ipecho.net/plain",
		"http://ifconfig.me/ip",
		"http://ifconfig.co",
		"https://myexternalip.com/raw",
		"http://checkip.dyndns.org"}
	for _, srv := range serversList {
		retbytes, err := sutils.HTTPDownLoadUrl(srv, "GET", "", "", false, time.Millisecond*2000)
		strinput := string(retbytes)
		if err == nil {
			if ipv4 := sutils.StringGetIpv4(strinput); len(ipv4) != 0 {
				//				fmt.Printf("\nlen regex %+v\n", retregex)
				return ipv4
			}
		}
	}
	return ""
}

func DialExpec(addr, expect string, timeouts ...time.Duration) bool {
	timeout := time.Millisecond * 1000
	if len(timeouts) != 0 {
		timeout = timeouts[0]
	}
	nc, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer nc.Close()
	reply := make([]byte, len(expect)*2)
	nc.SetReadDeadline(time.Now().Add(timeout))
	n, err := nc.Read(reply)
	if err != nil {
		//		log.Warnf("String is not match %s", err.Error())
		return false
	}
	return sutils.StringContainsI(string(reply[:n]), expect)
}

func IsVnc(addr string, timeouts ...time.Duration) bool {
	return DialExpec(addr, "rfb", timeouts...)
}

func IsSsh(addr string, timeouts ...time.Duration) bool {
	return DialExpec(addr, "ssh", timeouts...)
}

const (
	// Stolen from https://godoc.org/golang.org/x/net/internal/iana,
	// can't import "internal" packages
	ProtocolICMP = 1
	//ProtocolIPv6ICMP = 58
)

func Ping(addr, iface string, timeouts ...time.Duration) (*net.IPAddr, time.Duration, error) {
	// Start listening for icmp replies
	timeout := time.Millisecond * 1000
	if len(timeouts) != 0 {
		timeout = timeouts[0]
	}
	listenAddr := "0.0.0.0"
	if len(iface) != 0 {
		// if sutils.StringContainsI(iface, "ppp") {
		//			defer sutils.TimeTrack(time.Now())
		// }
		if ip4, err := NetGetInterfaceIpv4Addr(iface); err == nil {
			//			fmt.Printf("\nip's%s is %s\n", iface, ip4)
			listenAddr = ip4
		} else {
			return nil, 0, fmt.Errorf("iface %s threre isnt ip4", iface)
		}
	}
	//	c, err := icmp.ListenPacket("ip4:1991", listenAddr+":1991")
	c := new(icmp.PacketConn)
	var err error
	if sutils.GOOS != "windows" {
		c, err = icmp.ListenPacket("udp4", listenAddr)
	} else {
		c, err = icmp.ListenPacket("ip4:icmp", listenAddr)
	}

	if err != nil {
		return nil, 0, err
	}
	defer c.Close()

	// Resolve any DNS (if used) and get the real IP of the target
	dstip4, err := ResolverDomain2Ip4(addr)
	if err != nil {
		//		panic(err)
		return nil, 0, err
	}

	dst, err := net.ResolveIPAddr("ip4", dstip4)
	if err != nil {
		//		panic(err)
		return nil, 0, err
	}
	// Make a new ICMP message
	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1, //<< uint(seq), // TODO
			Data: []byte(""),
		},
	}
	b, err := m.Marshal(nil)
	if err != nil {
		return dst, 0, err
	}

	// Send it
	start := time.Now()
	n, err := c.WriteTo(b, dst)
	if err != nil {
		return dst, 0, err
	} else if n != len(b) {
		return dst, 0, fmt.Errorf("got %v; want %v", n, len(b))
	}

	// Wait for a reply
	reply := make([]byte, 1500)
	err = c.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return dst, 0, err
	}
	n, peer, err := c.ReadFrom(reply)
	if err != nil {
		return dst, 0, err
	}
	duration := time.Since(start)

	// Pack it up boys, we're done here
	rm, err := icmp.ParseMessage(ProtocolICMP, reply[:n])
	if err != nil {
		return dst, 0, err
	}
	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		return dst, duration, nil
	default:
		return dst, 0, fmt.Errorf("got %+v from %v; want echo reply", rm, peer)
	}
}

func TimeZoneGet() (tz string) {
	tz = ""
	if retbytes, err := sutils.HTTPDownLoadUrl("https://freegeoip.app/csv", "GET", "", "", true, time.Second*10); err == nil {
		//118.70.67.69,VN,Vietnam,HN,Hanoi,Hanoi,,Asia/Ho_Chi_Minh,21.0313,105.8516,0
		//		fmt.Println("retbytes", string(retbytes))
		csv := strings.Split(string(retbytes), ",")
		if len(csv) == 11 {
			tz = csv[7]
		}
	} else {
		fmt.Println("TimeZoneGet", err)
	}
	return tz
}

func TimeGetUTCFromhttp() (gmtteme string) {
	gmtteme = ""
	client := http.Client{
		Timeout: 10000 * time.Millisecond,
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client.Transport = tr
	resp, err := client.Get("https://nist.time.gov/")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	headerdate := resp.Header.Get("Date")
	gmttimeArray := strings.Split(headerdate, " ")
	if len(gmttimeArray) == 6 && gmttimeArray[5] == "GMT" {
		monthmap := map[string]string{"Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
			"May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
			"Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12"}
		month, ok := monthmap[gmttimeArray[2]]
		if !ok {
			return
		}
		//		fmt.Println(gmtteme)
		return fmt.Sprintf("%s-%s-%s %s", gmttimeArray[3], month, gmttimeArray[1], gmttimeArray[4])
	}
	return
}

// GetNetworkTime retrieves the current UTC time from the remote NTP server
// It returns the go time.Time type of the current time in UTC.
func GetNetworkTime(ntpserver string, port int) (t *time.Time, err error) {
	var second, fraction uint64
	ip4 := ""
	if ip4, err = ResolverDomain2Ip4(ntpserver); err != nil {
		return nil, err
	}
	packet := make([]byte, 48)
	packet[0] = 0x1B

	//	addr, _ := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%s", ip4, strconv.Itoa(port)))
	//	conn, err := net.DialUDP("udp4", nil, addr)
	addr := fmt.Sprintf("%s:%s", ip4, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp4", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	_, err = conn.Write(packet)
	if err != nil {
		return nil, err
	}

	_, err = conn.Read(packet)
	if err != nil {
		return nil, err
	}

	//retrieve the bytes that we need for the current timestamp
	//data format is unsigned 64 bit long, big endian order
	//see: http://play.golang.org/p/6KRE-2Hq6n
	second = uint64(packet[40])<<24 | uint64(packet[41])<<16 | uint64(packet[42])<<8 | uint64(packet[43])
	fraction = uint64(packet[44])<<24 | uint64(packet[45])<<16 | uint64(packet[46])<<8 | uint64(packet[47])

	nsec := (second * 1e9) + ((fraction * 1e9) >> 32)

	now := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(nsec))

	return &now, nil
}

var __ntpServer = []string{"0.pool.ntp.org", "1.pool.ntp.org", "2.pool.ntp.org", "3.pool.ntp.org",
	"0.ubuntu.pool.ntp.org", "1.ubuntu.pool.ntp.org", "2.ubuntu.pool.ntp.org", "3.ubuntu.pool.ntp.org",
	"0.debian.pool.ntp.org", "1.debian.pool.ntp.org", "2.debian.pool.ntp.org", "3.debian.pool.ntp.org",
	"ntp.soracom.io"}

func TimeGetUTCFromInternet() (t string) { //get ntp protocol, then get http header
	for _, srv := range __ntpServer {
		if dt, err := GetNetworkTime(srv, 123); err == nil {
			//			log.Debug("Usfed ntp server ", srv, dt.UTC().String())
			tar := strings.Split(dt.UTC().String(), " ")
			//			2021-03-11 01:49:58.968944707 +0000 UTC
			//			for _, v := range tar {
			//				log.Debug(v)
			//			}
			return fmt.Sprintf("%s %s", tar[0], tar[1])
		}
	}
	return TimeGetUTCFromhttp() // get from header http
}

func GetOutboundIP(iface ...string) (string, error) {
	if (len(iface) != 0) && (len(iface[0]) != 0) {
		return NetGetInterfaceIpv4Addr(iface[0])
	} else {
		conn, err := net.DialTimeout("udp", "1.1.1.1:80", time.Second)
		if err != nil {
			//			log.Println(err)
			return "", err
		} else {
			defer conn.Close()
		}
		localAddr := conn.LocalAddr().(*net.UDPAddr)

		return localAddr.IP.String(), nil
	}
}

func GetDefaultIface() (string, error) {
	LanIP, err := GetOutboundIP()
	if err != nil {
		return "", err
	}
	return NetGetInameByIP(LanIP)
}

//infotype 0 interface name, 1 macaddr, 2 cidr, >2 lanip]
func NetGetInterfaceInfo(infotype int, ifaces ...string) (info string, err error) {
	// get all the system's or local machine's network interfaces
	ifname := ""
	if len(ifaces) == 0 {
		LanIP, err := GetOutboundIP()
		if err != nil {
			return "", err
		}
		if ifname, err = NetGetInameByIP(LanIP); err != nil {
			return "", err
		}
	} else {
		ifname = ifaces[0]
	}

	if interf, err := net.InterfaceByName(ifname); err != nil { // get interface from name
		return "", err
	} else {
		if infotype == IfaceIname { //name
			return interf.Name, nil
		} else if infotype == IfaceMacddr { //macaddr
			return interf.HardwareAddr.String(), nil
		} else {
			if addrs, err := interf.Addrs(); err == nil {
				for _, addr := range addrs {
					cidr := addr.String()

					if ipv4Addr := addr.(*net.IPNet).IP.To4(); ipv4Addr == nil { //only check ip4
						if infotype == IfaceIp6 {
							return cidr, nil
						} else {
							continue
						}
					}

					if infotype == IfaceCidr { //cidr
						if ip, ipnet, err := net.ParseCIDR(cidr); err == nil {
							ip = ip.To4()
							onces, _ := ipnet.Mask.Size()
							return fmt.Sprintf("%s/%d", ip.Mask(ipnet.Mask).String(), onces), nil
						}
						return cidr, nil //cidr
					} else if infotype == IfaceIp4 {
						return strings.Split(cidr, "/")[0], nil
					} else if infotype == IfaceMask {
						if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
							return net.IP(ipnet.Mask).String(), nil
							//							return ip.Mask(ipnet.Mask).String(), nil
						}
					}

				}
			}
		}
	}
	return "", errors.New("Not found infor for iface " + ifname)
}

func IpParserCIDR(cidr string) (maskip, defaultgateway string, err error) {
	//	nm := net.IPMask(maskip)
	if ip, ipnet, err1 := net.ParseCIDR(cidr); err1 == nil {
		//		ipnet.Mask.Size()
		gwip := ip.Mask(ipnet.Mask)
		gwip[len(gwip)-1] = gwip[len(gwip)-1] | 1
		maskip = net.IP(ipnet.Mask).String()
		return maskip, gwip.String(), nil
	} else {
		return "", "", err1
	}
}

func IpBetween(from net.IP, to net.IP, test net.IP) bool {
	if from == nil || to == nil || test == nil {
		fmt.Println("An ip input is nil") // or return an error!?
		return false
	}

	from16 := from.To16()
	to16 := to.To16()
	test16 := test.To16()
	if from16 == nil || to16 == nil || test16 == nil {
		fmt.Println("An ip did not convert to a 16 byte") // or return an error!?
		return false
	}

	if bytes.Compare(test16, from16) >= 0 && bytes.Compare(test16, to16) <= 0 {
		return true
	}
	return false
}

func IsPublicIP(IP net.IP) bool {
	if IP == nil || IP.IsLoopback() || IP.IsLinkLocalMulticast() || IP.IsLinkLocalUnicast() {
		return false
	}
	if ip4 := IP.To4(); ip4 != nil {
		switch true {
		case ip4[0] == 10:
			return false
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return false
		case ip4[0] == 192 && ip4[1] == 168:
			return false
		default:
			return true
		}
	}
	return false
}

func IpInc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func NetGetMacInterFace(interfaceName string) (macadd string, err error) {
	var ief *net.Interface
	if ief, err = net.InterfaceByName(interfaceName); err != nil { // get interface
		return
	}
	return ief.HardwareAddr.String(), nil
}

func NetGetInameByIP(ip string) (i string, err error) {
	interfaces, _ := net.Interfaces() //all ifaces
	ipTocheck := netaddr.ParseIP(ip)
	if len(ipTocheck) == 0 {
		return "", fmt.Errorf("ip is wrong format")
	}
	for _, interf := range interfaces {
		if addrs, err := interf.Addrs(); err == nil {
			for _, addr := range addrs {
				cidr := addr.String()
				ipset := new(netaddr.IPSet)
				if _, ipnet, err := netaddr.ParseCIDR(cidr); err == nil {
					ipset.InsertNet(ipnet)
					if ipset.Contains(ipTocheck) {
						// if strings.Contains(cidr, ip) {
						return interf.Name, nil
					}
				}
			}
		}
	}
	return "", errors.New("Can not match iface has ip " + ip)
}

func NetGetMacBytesInterFace(interfaceName string) (macadd []byte, err error) {
	var (
		ief *net.Interface
	)
	if ief, err = net.InterfaceByName(interfaceName); err != nil { // get interface
		return
	}
	return ief.HardwareAddr, nil
}

func NetGetMac(iface ...string) (macadd string, err error) {
	return NetGetInterfaceInfo(IfaceMacddr, iface...)
}

func NetIsIpv4(ip net.IP) bool {
	return strings.Contains(ip.String(), ".") //firtst ip4
}

func NetTCPClientSend(servAddr string, dataSend []byte) (retbytes []byte, err error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", servAddr)
	if err != nil {
		println("ResolveTCPAddr failed:", err.Error())
		return retbytes, err
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		println("Dial failed:", err.Error())
		return retbytes, err
	}

	defer conn.Close()

	_, err = conn.Write(dataSend)

	if err != nil {
		fmt.Println("Write to server failed:", err.Error())
		return retbytes, err
	}
	//	conn.Write(io.EOF)
	reply := make([]byte, 1024)

	n, err := conn.Read(reply)
	if err != nil {
		println("Write to server failed:", err.Error())
	}
	return reply[:n], err
}

func NetGetCIDR(iface ...string) (string, error) {
	return NetGetInterfaceInfo(IfaceCidr, iface...)
}

func NetGetDefaultGatewayOfIface(iface ...string) (string, error) {
	if stdout, stderr, err := sexec.ExecCommandShell(fmt.Sprintf(`ip r s dev %s | grep -m 1 -Poe 'via\s+[^\s]+' | sed -Ee 's/via\s+//g'`, iface), time.Second*3); err == nil {
		return string(stdout), nil
	} else {
		return "", fmt.Errorf("%s", string(stderr))
	}
}

func NetGetMask(iface ...string) (string, error) {
	return NetGetInterfaceInfo(IfaceMask, iface...)
}

func NetGetMacs(iface ...string) ([]string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var as []string
	for _, ifa := range ifas {
		a := ""

		if len(iface) != 0 {
			if ifa.Name == iface[0] {
				a = ifa.HardwareAddr.String()
			}
		} else {
			a = ifa.HardwareAddr.String()
		}

		if len(a) != 0 {
			as = append(as, a)
		}
	}
	return as, nil
}

func TimeUpdateFromInternet(tzone ...string) bool {
	var err error
	tz := TimeZoneGet()
	if len(tzone) != 0 && len(tzone[0]) != 0 {
		tz = tzone[0]
	}
	datetime := TimeGetUTCFromInternet()
	if (len(tz) != 0) && (len(datetime) != 0) {
		errsetdatetime := false
		if _, _, err = sexec.ExecCommandShell(fmt.Sprintf(`timedatectl set-timezone "%s"`, tz), time.Second*1); err == nil {
			log.Println("Update timezone to", tz)
		} else {
			errsetdatetime = true
			log.Println("Can not update timezone ", err)
		}
		if _, _, err := sexec.ExecCommand(`date`, `--utc`, `--set`, datetime); err != nil {
			errsetdatetime = true
			log.Println("Can not update timedate", err)
		} else {
			log.Println("Update datetime [GMT] to", datetime)
		}
		if !errsetdatetime {
			return true
		}
	}
	return false
}

func NetDiscoveryConfigPort(port int) {
	mdns.InitPort(port)
}

func IpIsPrivate(ip string) bool {

	//    # https://en.wikipedia.org/wiki/Private_network
	for _, pattern := range []string{`^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$`, `^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$`,
		`^192\.168\.\d{1,3}.\d{1,3}$`, `^172.(1[6-9]|2[0-9]|3[0-1]|172).[0-9]{1,3}.[0-9]{1,3}$`} {
		if matched, err := regexp.Match(pattern, []byte(ip)); err == nil && matched {
			return true
		}
	}
	return false
}

func IpGetDefault(ipstr string) (mask, gw string, err error) {
	if ip := net.ParseIP(ipstr); ip != nil {
		ipmask := ip.DefaultMask()
		mask := net.IP(ipmask).String()

		ipgw := ip.Mask(ipmask)
		ipgw[len(ipgw)-1] = ipgw[len(ipgw)-1] | 1
		gw = net.IP(ipgw).String()
		return mask, gw, nil
	} else {
		return mask, gw, fmt.Errorf("ip error")
	}
}

func IpFlush(ifi string) error {
	cmd2run := fmt.Sprintf(`ifi=%s; for i in $(ip r show  dev ${ifi} | grep -oPe '^[^\s]+' | sort -u -k1); do ip r del $i dev ${ifi}; done; ip addr flush dev ${ifi};`, ifi)
	if _, errstd, err := sexec.ExecCommandShell(cmd2run, time.Second*5); err == nil {
		return nil
	} else {
		return fmt.Errorf("%s", string(errstd))
	}
}

func IpDhcpRenew(ifi string, timeouts ...time.Duration) error {
	timeout := time.Second * 30
	if len(timeouts) != 0 {
		timeout = timeouts[0]
	}
	cmd2run := fmt.Sprintf("dhclient  %s", ifi)
	if _, errstd, err := sexec.ExecCommandShell(cmd2run, timeout); err == nil {
		return nil
	} else {
		return fmt.Errorf("%s", string(errstd))
	}
}

func IpConfigAuto(ipcidr string, ifaces ...string) error {
	pass := false

	ifiname := "eth0"
	if len(ifaces) != 0 {
		ifiname = ifaces[0]
	} else {
		if _, err := net.InterfaceByName(ifiname); err != nil {
			if ifitmp, err := GetDefaultIface(); err == nil {
				ifiname = ifitmp
			} else {
				return fmt.Errorf("can not get default iface")
			}
		}
	}

	if _, err := NetGetInterfaceIpv4Addr(ifiname); err == nil {
		return nil
	}

	ifi, err := net.InterfaceByName(ifiname)
	if err != nil {
		return err
	}

	ipset := new(netaddr.IPSet)
	if _, ipnet, err := netaddr.ParseCIDR(ipcidr); err == nil {
		ipset.InsertNet(ipnet)
	} else if netip := netaddr.ParseIP(ipcidr); netip == nil {
		ipset.Insert(netip)
	}
	ips := ipset.GetIPs(256)
	if len(ips) <= 0 {
		return fmt.Errorf("empty ips list")
	}
	iptest := ips[len(ips)-1]
	ipmask := iptest.DefaultMask()

	mask := net.IP(ipmask).String()

	ipgws := []net.IP{}
	ipgw := iptest.Mask(ipmask)

	for _, v := range []byte{1, 2, 22, 185} {
		ipgw[len(ipgw)-1] = v
		//		ipgw[len(ipgw)-1] = ipgw[len(ipgw)-1] | v
		ipgws = append(ipgws, ipgw)
	}

	defer func() {
		if !pass {
			IpFlush(ifiname)
		}
	}()
	//	mask, gw, err = IpGetDefault(ip.String())
	//	fmt.Println("Ip Check", ips)
	for i := len(ips) - 1; i >= 0; i-- {
		ip := ips[i]
		if func() bool {
			for _, ipgw := range ipgws {
				if ip.String() == net.IP(ipgw).String() {
					return true
				}
			}
			return false
		}() {
			continue
		}

		for _, ipgw := range ipgws {
			gw := net.IP(ipgw).String()

			if err := IpConfig(ip.String(), mask, gw, ifaces...); err == nil {
				//			fmt.Println("Cheking ", ip.String(), ipgw)
				if mac, err := arp.PingMac(ipgw, ifi, time.Millisecond*85); err == nil {
					fmt.Printf("Gateway %s Mac -> %s", ipgw, mac)
					for j := 2; j < len(ips); j++ {
						ipcheck := ips[j]
						fmt.Println("checking ", ipcheck.String(), ip.String(), ipgw)
						if ipcheck.String() == ip.String() {
							continue
						}
						if _, err := arp.PingMac(ipcheck, ifi, time.Millisecond*85); nil != err {
							if err := IpConfig(ipcheck.String(), mask, gw, ifaces...); err == nil {
								pass = true
								return nil
							}
						}
					}
					//				return nil
				}
			}
		}
		//else {
		//			fmt.Printf("IpConfig error %s: %s", ip.String(), err.Error())
		//		}
	}

	return fmt.Errorf("can not config %s", ipcidr)
}

func IpConfig(ipstr, maskstr, gwipstr string, ifaces ...string) error {
	if len(ipstr) != 0 || len(maskstr) != 0 {
		ifi := "eth0"
		if len(ifaces) != 0 {
			ifi = ifaces[0]
		} else {
			if _, err := net.InterfaceByName(ifi); err != nil {
				if ifitmp, err := GetDefaultIface(); err == nil {
					ifi = ifitmp
				} else {
					return fmt.Errorf("can not get default iface")
				}
			}
		}
		cidrstr := ""
		cirdbits := 0
		if ip := net.ParseIP(ipstr); ip != nil {
			if len(maskstr) == 0 || maskstr == "0.0.0.0" {
				maskstr = net.IP(ip.DefaultMask()).String()
			}
		} else {
			return fmt.Errorf("ip %s is wrong", maskstr)
		}

		if mask := net.ParseIP(maskstr); mask == nil {
			return fmt.Errorf("mask %s is wrong", maskstr)
		} else {
			ip := net.ParseIP(ipstr)
			ipmask := net.IPMask(mask.To4())

			if len(gwipstr) == 0 {
				ipgw := ip.Mask(ipmask)
				ipgw[len(ipgw)-1] = ipgw[len(ipgw)-1] | 1
				gwipstr = net.IP(ipgw).String()
			}

			cirdbits, _ = ipmask.Size()
			cidrstr = fmt.Sprintf("%s/%d", ip.Mask(ipmask).String(), cirdbits)
		}
		//IpParserCIDR(cidr)
		//ip a add 192.168.1.200/255.255.255.0 dev eth0
		//cmd2run := fmt.Sprintf("ifconfig %s %s netmask %s", ifi, ipstr, maskstr)
		//ip addr flush dev eth1

		if curIp, err := NetGetInterfaceIpv4Addr(ifi); err == nil && curIp == ipstr {
			if curMask, err := NetGetMask(ifi); err == nil && curMask == maskstr {
				//				fmt.Printf("Interface %s has been configured correctly before [%s/%s]", ifi, curIp, curMask)
				return nil
			}
		}
		for {
			IpFlush(ifi)
			cmd2run := fmt.Sprintf("ip a add %s/%s dev %s brd +", ipstr, maskstr, ifi)
			if _, errstd, err := sexec.ExecCommandShell(cmd2run, time.Second*3); err == nil {
				//if _, errstd, err := sexec.ExecCommand("ip", "ipaddr", Gvar.lanip, Gvar.lanmask, Gvar.langw, Gvar.landns); err == nil {
				//ipOne = true ip route add ${cidr} via ${gw} dev ${ifi} ||
				//				cmd2run = fmt.Sprintf("cidr=%s;gw=%s;ifi=%s; ip link set ${ifi} allmulticast on; ip link set ${ifi} allmulticast on; ip route add ${cidr} dev ${ifi}", cidrstr, gwipstr, ifi)

				cmd2run = fmt.Sprintf("cidr=%s;gw=%s;ifi=%s; ip link set ${ifi} allmulticast on; ip link set ${ifi} allmulticast on; ip r a default dev ${ifi} via ${gw} metric 1985", cidrstr, gwipstr, ifi)
				if _, stderr, err := sexec.ExecCommandShell(cmd2run, time.Second*3); err != nil {
					log.Warnf("Can not route (%s) [%s] %s", ipstr, cmd2run, string(stderr))
				}
				//for jetson only, no longer needed
				//				cmd2run = fmt.Sprintf(`nmcli connection modify "Wired connection 1" ipv4.method manual ipv4.addresses "%s/%s" ipv4.gateway %s`, ipstr, cirdbits, gwipstr)
				//				if _, err := gonmmm.NMRunCommand(cmd2run); err != nil {
				//					log.Debug("Cannot use nmcli to set ip ", err.Error())
				//				}
				return nil
			} else {
				if err := IpDhcpRenew(ifi); err == nil {
					return fmt.Errorf("can not confiture ip: %s so restore use dhcp ", string(errstd))
				} else {
					return fmt.Errorf("can not confiture ip: %s", string(errstd))
				}
			}
		}
	} else {
		return fmt.Errorf("can not confiture ip with zero ip and mask")
	}
}

func MacFromIP(ip2check string, ifaceFlags ...string) (info string, err error) {

	durFlag := time.Millisecond * 500
	diface, _ := NetGetInterfaceInfo(IfaceIname)

	ifaceFlag := diface
	if len(ifaceFlags) != 0 {
		ifaceFlag = ifaceFlags[0]
	}
	// Ensure valid network interface
	ifi, err := net.InterfaceByName(ifaceFlag)
	if err != nil {
		return info, err
	}

	// Set up ARP client with socket
	c, err := arp.Dial(ifi)
	if err != nil {
		return info, err
	}
	defer c.Close()

	// Set request deadline from flag
	if err := c.SetDeadline(time.Now().Add(durFlag)); err != nil {
		return info, err
	}

	// Request hardware address for IP address
	ip := net.ParseIP(ip2check).To4()
	mac, err := c.Resolve(ip)
	if err != nil {
		return info, err
	}

	//	log.Printf("%s -> %s", ip, mac)
	return mac.String(), nil
	//	return fmt.Sprintf("%s -> %s", ip, mac), nil
}

func NetInitDiscoveryServer(ipService interface{}, serviceport interface{}, id, serviceName string, info interface{}, ifaceName ...string) (s *mdns.Server, err error) {

	if len(serviceName) == 0 {
		serviceName = "_signage._tcp"
	}
	//(instance, service, domain, hostName string, port int, ips []net.IP, txt []string)
	service, err := mdns.NewMDNSService(id, serviceName, "", "", serviceport, ipService, info)

	if err != nil {
		fmt.Println("Cannot create config mdnsServer", err)
		return nil, err
	}
	var iface *net.Interface
	if len(ifaceName) != 0 {
		if ief, err := net.InterfaceByName(ifaceName[0]); err == nil { // get interface
			iface = ief
		}
	}
	// Create the mDNS server, defer shutdown
	if s, err = mdns.NewServer(&mdns.Config{Zone: service, Iface: iface}); err != nil {
		fmt.Println("Cannot start mdnsServer", err)
		return nil, err
	} else {
		//		log.Print(s.Config.Zone.(*mdns.MDNSService).Port)
		return s, nil
	}
	//	defer s.Shutdown()
}

func NetDiscoveryQueryServiceEntry(serviceName, domain string, timeout time.Duration, ifaceNames ...string) []*mdns.ServiceEntry {
	serviceInfo := make([]*mdns.ServiceEntry, 0)
	// Make a channel for results and start listening
	entriesCh := make(chan *mdns.ServiceEntry, 16)
	mutex := &sync.Mutex{}
	go func() {
		for entry := range entriesCh {
			// fmt.Printf("Got new signage entry: %v\n", entry)
			mutex.Lock()
			serviceInfo = append(serviceInfo, entry)
			mutex.Unlock()
		}
	}()

	if len(serviceName) == 0 {
		serviceName = "_signage._tcp"
	}
	params := mdns.DefaultParams(serviceName)
	params.WantUnicastResponse = true
	if len(ifaceNames) != 0 {
		if ief, err := net.InterfaceByName(ifaceNames[0]); err == nil { // get interface
			//			log.Info("NetDiscoveryQuery on interface ", ifaceNames[0])
			params.Interface = ief
		} else {
			return serviceInfo
		}
	} else {
		log.Errorf("NetDiscoveryQuery on default interface [not for interface %s]", ifaceNames[0])
	}
	params.Domain = ""
	params.Entries = entriesCh
	if timeout == 0 {
		timeout = time.Second * 2
	}
	params.Timeout = timeout
	params.Domain = domain
	if err := mdns.Query(params); err != nil {
		log.Error("mdns.Query err:", err)
	}
	// Start the lookup
	//	mdns.Lookup("_signage._tcp", entriesCh)
	close(entriesCh)
	return serviceInfo
}

func NetDiscoveryQuery(serviceName string, timeout time.Duration, ifaceNames ...string) []*DiscoveryInfo {
	serviceInfo := make([]*DiscoveryInfo, 0)
	// Make a channel for results and start listening
	entriesCh := make(chan *mdns.ServiceEntry, 16)
	mutex := &sync.Mutex{}
	if len(serviceName) == 0 {
		serviceName = "_signage._tcp"
	}
	if serviceName == "all" {
		serviceName = ""
	}
	params := mdns.DefaultParams(serviceName)
	params.WantUnicastResponse = true
	if len(ifaceNames) != 0 {
		if ief, err := net.InterfaceByName(ifaceNames[0]); err == nil { // get interface
			//			log.Info("NetDiscoveryQuery on interface ", ifaceNames[0])
			params.Interface = ief
		} else {
			return serviceInfo
		}
	} else {
		log.Errorf("NetDiscoveryQuery on default interface [not for interface %s]", ifaceNames[0])
	}
	params.Domain = ""
	params.Entries = entriesCh
	if timeout == 0 {
		timeout = time.Second * 2
	}
	params.Timeout = timeout

	go func() {
		for entry := range entriesCh {
			// fmt.Printf("Got new signage entry: %v\n", entry)
			// serviceAddr := fmt.Sprintf("%s.%s.", strings.Trim(params.Service, "."), strings.Trim(params.Domain, "."))
			// if !strings.HasSuffix(entry.Name, serviceAddr) {
			// 	continue
			// }
			service := new(DiscoveryInfo)
			service.Ip4 = entry.AddrV4.String()
			service.Port = entry.Port
			service.Info = entry.InfoFields
			service.Name = entry.Name
			service.Host = entry.Host
			mutex.Lock()
			serviceInfo = append(serviceInfo, service)
			mutex.Unlock()
		}
	}()

	if err := mdns.Query(params); err != nil {
		log.Error("mdns.Query err:", err)
	}
	// Start the lookup
	//	mdns.Lookup("_signage._tcp", entriesCh)
	close(entriesCh)
	return serviceInfo
}

func NetDiscoveryQueryCCC(servicename string, ifaceName ...string) (deviceList []DeviceCCCInfo) {
	ifaceall := []string{}
	if len(ifaceName) != 0 {
		if ifaceName[0] == "all" || len(ifaceName[0]) == 0 {
			ifaceall = IfaceGetAllName(true)
		} else {
			ifaceall = ifaceName
		}
	} else {
		if deif, err := NetGetInterfaceInfo(IfaceIname); err == nil {
			ifaceall = []string{deif}
		}
	}
	//	log.Warn("Interface discovery ", ifaceall)
	//	fmt.Println()
	var wg sync.WaitGroup
	lockwrire := &sync.Mutex{}
	for _, iface := range ifaceall {
		wg.Add(1)

		go func(iface string) {
			defer func() {
				wg.Done()
			}()
			serviceInfo := NetDiscoveryQuery(servicename, time.Second*4, iface)
			//		serviceInfo := NetDiscoveryQuery(servicename, time.Second*1, ifaceName...)
			//			fmt.Printf("\n\n\nDiscoveryDevice\n%s\n%#v\n%#v\n", servicename, serviceInfo, iface)
			for _, entry := range serviceInfo {
				// fmt.Printf("entry\n%s\n%v\n", entry.Name, entry)
				sig := DeviceCCCInfo{}
				sig.IP = entry.Ip4
				sig.Port = entry.Port
				netry := len(entry.Info)
				if netry >= 3 {
					// if (netry >= 3) && (entry.Info[netry-1] == sig.IP) {
					sig.Serial_number = entry.Info[0]
					sig.Device_id = entry.Info[1]
					sig.From = iface
					sig.Extra = []string{}
					if netry >= 4 {
						sig.Extra = entry.Info[2:(netry - 1)]
					}
					sig.LastDiscovery = time.Now()
					lockwrire.Lock()
					deviceList = append(deviceList, sig)
					lockwrire.Unlock()
				}

			}
		}(iface)
	}
	wg.Wait()

	return deviceList
}

func OnvifDiscovery(ifaceName ...string) []CamerasInfo {
	ifaceall := []string{}
	if len(ifaceName) != 0 {
		if ifaceName[0] == "all" || ifaceName[0] == "" {
			ifaceall = IfaceGetAllName(true)
		} else {
			ifaceall = ifaceName
		}
	} else {
		if deif, err := NetGetInterfaceInfo(IfaceIname); err == nil {
			ifaceall = []string{deif}
		}
	}
	var wg sync.WaitGroup
	cameralist := []CamerasInfo{}
	lockwrire := &sync.Mutex{}

	for _, iface := range ifaceall {
		wg.Add(1)
		go func(iface string) {
			defer func() {
				wg.Done()
			}()
			devices := wsdiscovery.SendProbe(iface, nil, []string{"dn:NetworkVideoTransmitter"}, map[string]string{"dn": "http://www.onvif.org/ver10/network/wsdl"})
			for _, j := range devices {
				// log.Println("wsdiscovery device:" + j)
				doc := etree.NewDocument()
				if doc == nil {
					continue
				}

				if err := doc.ReadFromString(j); err != nil {
					//			context.String(http.StatusNotAcceptable, err.Error())
					//					return
				} else {
					endpoints := doc.Root().FindElement("./Body/ProbeMatches/ProbeMatch/XAddrs")
					if endpoints == nil {
						continue
					}
					scopes := doc.Root().FindElement("./Body/ProbeMatches/ProbeMatch/Scopes")
					if scopes == nil {
						continue
					}
					urn := doc.Root().FindElement("./Body/ProbeMatches/ProbeMatch/EndpointReference/Address")
					//				types := doc.Root().FindElement("./Body/ProbeMatches/ProbeMatch/Types")
					if urn == nil {
						continue
					}
					uuid := urn.Text()
					uuid = sregexp.New(`[^:]+$`).FindString(uuid)
					uuid = strings.ReplaceAll(sregexp.New(`[^:]+$`).FindString(uuid), "-", "")
					flag := false

					for _, v := range cameralist {
						if v.UUID == uuid {
							flag = true
							break
						}
					}
					if flag {
						continue
					}
					flag = false

					cam := CamerasInfo{}
					cam.UUID = uuid
					cam.XADDR = sregexp.New(`[^\s]+([0-9]+\.){3}[0-9]+[^\s]+`).FindString(endpoints.Text())

					cam.IP = sregexp.New(`([0-9]+\.){3}[0-9]+`).FindString(endpoints.Text())

					if vs := sregexp.New(`onvif:\/\/www\.onvif\.org\/name\/([^\s]+)`).FindStringSubmatch(scopes.Text()); len(vs) != 0 {
						cam.Name = vs[1]
					}

					if vs := sregexp.New(`onvif:\/\/www\.onvif\.org\/hardware\/([^\s]+)`).FindStringSubmatch(scopes.Text()); len(vs) != 0 {
						cam.Hardware = vs[1]
					}

					if vs := sregexp.New(`onvif:\/\/www\.onvif\.org\/location\/([^\s]+)`).FindStringSubmatch(scopes.Text()); len(vs) != 0 {
						cam.Location = vs[1]
					}

					if flag {
						continue
					}
					//					log.Println("Device: ", uuid)

					cam.From = iface
					lockwrire.Lock()
					cameralist = append(cameralist, cam)
					lockwrire.Unlock()
				}
			}
		}(iface)
	}
	wg.Wait()
	//	log.Println("cameralist: ", cameralist)
	return cameralist
}

func NMCreateHostPost(ifacename, conname, ssid, password string) error {
	//connection.autoconnect
	if gonmmm.NMConIsExist(conname) {
		keymgmt := gonmmm.NMConGetField(conname, "802-11-wireless-security.key-mgmt")
		if keymgmt == "none" {
			if password != gonmmm.NMConGetField(conname, "802-11-wireless-security.wep-key0") {
				if err := gonmmm.NMConModField(conname, "802-11-wireless-security.wep-key0", password); err != nil {
					return err
				}
			}
		} else if keymgmt == "wpa-psk" {
			if password != gonmmm.NMConGetField(conname, "802-11-wireless-security.psk") {
				if err := gonmmm.NMConModField(conname, "802-11-wireless-security.psk", password); err != nil {
					return err
				}
			}
		}
		ssidTmp := gonmmm.NMConGetField(conname, "802-11-wireless.ssid")

		if ssidTmp != ssid {
			if err := gonmmm.NMConModField(conname, "wifi.ssid", ssid); err != nil {
				return err
			}
		}

		return nil
	}

	_, err := gonmmm.NMRunCommand(fmt.Sprintf("dev wifi hotspot ifname %s con-name %s ssid %s password %s", ifacename, conname, ssid, password))
	return err
}

func NMConnectWifi(ifacename, ssid, password string) error {
	if gonmmm.NMConIsExist(ssid) {
		if pwd := gonmmm.NMConGetField(ssid, "802-11-wireless-security.psk"); pwd == password {
			return nil
		} else {
			return gonmmm.NMConModField(ssid, "802-11-wireless-security.psk", password)
		}
	}
	_, err := gonmmm.NMRunCommand(fmt.Sprintf("dev wifi connect %s ifname %s password %s", ssid, ifacename, password))
	return err
}

func IfaceRestart(ifacname string) bool {
	cmd2run := fmt.Sprintf("iface=%s; ip link set down  ${iface};  ip link set up ${iface}", ifacname)
	if _, _, err := sexec.ExecCommandShell(cmd2run, time.Millisecond*5000); err == nil {
		return true
	}
	return false
}

func GetFreePort(isUdp ...bool) (int, error) {
	if len(isUdp) != 0 && isUdp[0] {
		return GetFreeUdpPort()
	}
	return GetFreeTcpPort()
}

func GetFreeTcpPort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func GetFreeUdpPort() (int, error) {
	addr, err := net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenUDP("udp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port, nil
}

func GetFreePorts(count int, isUdp ...bool) ([]int, error) {
	if len(isUdp) != 0 && isUdp[0] {
		return GetFreeUdpPorts(count)
	}
	return GetFreeTcpPorts(count)
}

func GetFreeUdpPorts(count int) ([]int, error) {
	var ports []int
	for i := 0; i < count; i++ {
		if port, err := GetFreeTcpPort(); err == nil {
			ports = append(ports, port)
		} else {
			return nil, err
		}
	}
	return ports, nil
}

func GetFreeTcpPorts(count int) ([]int, error) {
	var ports []int
	for i := 0; i < count; i++ {
		if port, err := GetFreeUdpPort(); err == nil {
			ports = append(ports, port)
		} else {
			return nil, err
		}
	}
	return ports, nil
}
