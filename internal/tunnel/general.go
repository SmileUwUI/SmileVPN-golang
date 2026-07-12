package tunnel

import (
	"net"
)

type Tunnel interface {
	Name() string
	Read(packet []byte) (int, error)
	Write(packet []byte) (int, error)
	IP() net.IP
	Netmask() net.IPMask
	MTU() int
	SetIP(ip net.IP, netmask net.IPMask) error
	Up(excludeIPs []string, setDefaultRoute, createNAT, clearConntrack bool) error
	Down(deleteNAT, delDefaultRoute, clearConntrack bool) error
	Close(deleteNAT, delDefaultRoute, clearConntrack bool) error
	IsRunning() bool
}

func IPs(cidr string) ([]net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for currIP := ip.Mask(ipnet.Mask); ipnet.Contains(currIP); inc(currIP) {
		temp := make(net.IP, len(currIP))
		copy(temp, currIP)
		ips = append(ips, temp)
	}

	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
