package server

import (
	"net"
	"sync"
)

type IPPool struct {
	mu      sync.Mutex
	network *net.IPNet
	usedIPs map[string]bool
	nextIP  net.IP
}

func NewIPPool(cidr string) (*IPPool, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	pool := &IPPool{
		network: network,
		usedIPs: make(map[string]bool),
		nextIP:  network.IP,
	}

	pool.nextIP = incrementIP(pool.nextIP)
	pool.nextIP = incrementIP(pool.nextIP)

	return pool, nil
}

func (p *IPPool) AcquireIP() net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()

	startIP := p.nextIP
	for {
		ipStr := p.nextIP.String()
		if !p.usedIPs[ipStr] && p.network.Contains(p.nextIP) {
			p.usedIPs[ipStr] = true
			p.nextIP = incrementIP(p.nextIP)

			ipCopy := make(net.IP, len(p.nextIP))
			copy(ipCopy, p.nextIP)
			decrementIP(ipCopy)
			return ipCopy
		}

		p.nextIP = incrementIP(p.nextIP)

		if p.nextIP.Equal(startIP) {
			return nil
		}
	}
}

func (p *IPPool) ReleaseIP(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.usedIPs, ip.String())
}

func incrementIP(ip net.IP) net.IP {
	result := make(net.IP, len(ip))
	copy(result, ip)

	for i := len(result) - 1; i >= 0; i-- {
		result[i]++
		if result[i] != 0 {
			break
		}
	}
	return result
}

func decrementIP(ip net.IP) net.IP {
	result := make(net.IP, len(ip))
	copy(result, ip)

	for i := len(result) - 1; i >= 0; i-- {
		result[i]--
		if result[i] != 255 {
			break
		}
	}
	return result
}
