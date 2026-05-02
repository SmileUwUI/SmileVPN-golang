package tunnel

import (
	"net"
	"runtime"
)

type Tunnel interface {
	Name() string
	Read(packet []byte) (int, error)
	Write(packet []byte) (int, error)
	IP() net.IP
	Netmask() net.IPMask
	MTU() int
	SetIP(ip net.IP, netmask net.IPMask) error
	Up(excludeIPs []string, setDefaultRoute bool) error
	Down() error
	Close() error
	IsRunning() bool
	Stats() (*TunnelStats, error)
}

type TunnelStats struct {
	RXBytes   uint64
	RXPackets uint64
	TXBytes   uint64
	TXPackets uint64
	LastError error
}

func NewTunnel(name string, mtu int, address net.IP, netmask net.IPMask) (tunnel Tunnel, err error) {
	switch runtime.GOOS {
	case "linux":
		return NewLinuxTunnel(name, mtu, address, netmask)
	default:
		return nil, nil
	}
}
