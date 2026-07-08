package tunnel

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

type LinuxTunnel struct {
	iface    *water.Interface
	name     string
	ip       net.IP
	netmask  net.IPMask
	mtu      int
	running  bool
	mu       sync.RWMutex
	oldGW    string
	oldIface string
}

func NewLinuxTunnel(name string, mtu int, address net.IP, netmask net.IPMask) (Tunnel, error) {
	waterConfig := water.Config{
		DeviceType: water.TUN,
	}

	if name != "" {
		waterConfig.Name = name
	}

	iface, err := water.New(waterConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN: %w", err)
	}

	tunnel := &LinuxTunnel{
		iface:   iface,
		name:    iface.Name(),
		mtu:     mtu,
		running: false,
	}

	if address != nil {
		if err := tunnel.SetIP(address, netmask); err != nil {
			return nil, err
		}
	}

	if mtu > 0 {
		err = tunnel.SetMTU(mtu)
		if err != nil {
			return nil, err
		}
	}

	return tunnel, nil
}

func (t *LinuxTunnel) Name() string {
	return t.name
}

func (t *LinuxTunnel) Read(packet []byte) (int, error) {
	return t.iface.Read(packet)
}

func (t *LinuxTunnel) Write(packet []byte) (int, error) {
	return t.iface.Write(packet)
}

func (t *LinuxTunnel) IP() net.IP {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.ip
}

func (t *LinuxTunnel) Netmask() net.IPMask {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.netmask
}

func (t *LinuxTunnel) MTU() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.mtu
}

func (t *LinuxTunnel) SetIP(ip net.IP, netmask net.IPMask) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.ip != nil {
		err := exec.Command("ip", "addr", "del",
			fmt.Sprintf("%s/%d", t.ip, t.getPrefixLen()),
			"dev", t.name).Run()

		if err != nil {
			return err
		}
	}

	prefixLen, _ := netmask.Size()
	cmd := exec.Command("ip", "addr", "add",
		fmt.Sprintf("%s/%d", ip.String(), prefixLen),
		"dev", t.name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set IP: %w", err)
	}

	t.ip = ip
	t.netmask = netmask
	return nil
}

func (t *LinuxTunnel) GetIP() net.IP {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.ip
}

func (t *LinuxTunnel) SetMTU(mtu int) error {
	cmd := exec.Command("ip", "link", "set", "dev", t.name, "mtu", fmt.Sprintf("%d", mtu))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}
	t.mtu = mtu
	return nil
}

func (t *LinuxTunnel) saveDefaultRoute() error {
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	parts := strings.Fields(string(output))
	for i, part := range parts {
		if part == "via" && i+1 < len(parts) {
			t.oldGW = parts[i+1]
		}
		if part == "dev" && i+1 < len(parts) {
			t.oldIface = parts[i+1]
		}
	}

	return nil
}

func (t *LinuxTunnel) restoreDefaultRoute() error {
	err := exec.Command("ip", "route", "del", "default").Run()

	if err != nil {
		return err
	}

	if t.oldGW != "" && t.oldIface != "" {
		cmd := exec.Command("ip", "route", "add", "default", "via", t.oldGW, "dev", t.oldIface)
		return cmd.Run()
	}

	return nil
}

func (t *LinuxTunnel) SetupDefaultRoute() error {
	if err := t.saveDefaultRoute(); err != nil {
		return err
	}

	err := exec.Command("ip", "route", "del", "default").Run()
	if err != nil {
		return err
	}

	cmd := exec.Command("ip", "route", "add", "default", "dev", t.name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set default route to TUN: %w", err)
	}

	return nil
}

func (t *LinuxTunnel) AddRoutes(routes []*net.IPNet) error {
	for _, route := range routes {
		if route == nil {
			continue
		}

		err := exec.Command("ip", "route", "del", route.String()).Run()
		if err != nil {
			return err
		}

		cmd := exec.Command("ip", "route", "add", route.String(), "dev", t.name)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add route %s: %w", route.String(), err)
		}

	}
	return nil
}

func (t *LinuxTunnel) DeleteRoutes(routes []*net.IPNet) error {
	for _, route := range routes {
		if route == nil {
			continue
		}

		err := exec.Command("ip", "route", "del", route.String(), "dev", t.name).Run()
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *LinuxTunnel) Up(excludeIPs []string, setDefaultRoute, createNAT, clearConntrack bool) error {
	routeInfo, err := getDefaultRouteNetlink()
	if err != nil {
		return fmt.Errorf("error retrieving route information: %w", err)
	}

	var cmd *exec.Cmd
	for _, ip := range excludeIPs {
		cmd = exec.Command("ip", "route", "add", ip,
			"via", routeInfo.Gateway, "dev", routeInfo.Interface)

		if err := cmd.Run(); err != nil && err.Error() != "exit status 2" {
			return fmt.Errorf("failed to add server route: %w", err)
		}

	}

	cmd = exec.Command("ip", "link", "set", "dev", t.name, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring up interface: %w", err)
	}

	err = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	if err != nil {
		return fmt.Errorf("ip_forward installation error: %w", err)
	}

	if createNAT {
		err = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", fmt.Sprintf("%s/%d", t.ip, t.getPrefixLen()), "-o", routeInfo.Interface, "-j", "MASQUERADE").Run()
		if err != nil {
			return fmt.Errorf("iptables creation error: %w", err)
		}
	}

	if setDefaultRoute {
		if err := t.SetupDefaultRoute(); err != nil {
			return err
		}
	}

	if clearConntrack {
		allIPs, err := IPs(fmt.Sprintf("%s/%d", t.ip, t.getPrefixLen()))
		if err != nil {
			return fmt.Errorf("Error parsing: %v", err)
		}

		for _, ip := range allIPs {
			outgoing := exec.Command("conntrack", "-D", "-s", ip.String())
			if err := outgoing.Run(); err != nil {
				if !strings.Contains(err.Error(), "exit status 1") {
					fmt.Printf("Error deleting outgoing connections: %v\n", err)
				}
			}

			input := exec.Command("conntrack", "-D", "-d", ip.String())
			if err := input.Run(); err != nil {
				if !strings.Contains(err.Error(), "exit status 1") {
					fmt.Printf("Error deleting input connections: %v\n", err)
				}
			}
		}
	}

	t.running = true
	return nil
}

func (t *LinuxTunnel) Down(deleteNAT, delDefaultRoute, clearConntrack bool) error {
	var cmd *exec.Cmd
	if delDefaultRoute {
		err := t.restoreDefaultRoute()
		if err != nil {
			return err
		}
		cmd = exec.Command("ip", "link", "set", "dev", t.name, "down")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to bring down interface: %v", err)
		}
	}

	if deleteNAT {
		cmd = exec.Command("iptables", "-t", "nat", "-F")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to deleted iptables NAT: %v", err)
		}
	}

	allIPs, err := IPs(fmt.Sprintf("%s/%d", t.ip, t.getPrefixLen()))
	if err != nil {
		return fmt.Errorf("Error parsing: %v", err)
	}

	if clearConntrack {
		for _, ip := range allIPs {
			outgoing := exec.Command("conntrack", "-D", "-s", ip.String())
			if err := outgoing.Run(); err != nil {
				if !strings.Contains(err.Error(), "exit status 1") {
					fmt.Printf("Error deleting outgoing connections: %v\n", err)
				}
			}

			input := exec.Command("conntrack", "-D", "-d", ip.String())
			if err := input.Run(); err != nil {
				if !strings.Contains(err.Error(), "exit status 1") {
					fmt.Printf("Error deleting input connections: %v\n", err)
				}
			}
		}
	}

	t.running = false
	return nil
}

func (t *LinuxTunnel) Close(deleteNAT, delDefaultRoute, clearConntrack bool) error {
	err := t.Down(deleteNAT, delDefaultRoute, clearConntrack)
	if err != nil {
		return err
	}
	return t.iface.Close()
}

func (t *LinuxTunnel) IsRunning() bool {
	return t.running
}

func (t *LinuxTunnel) getPrefixLen() int {
	if t.netmask == nil {
		return 24
	}
	prefixLen, _ := t.netmask.Size()
	return prefixLen
}

type RouteInfo struct {
	Gateway   string
	Interface string
	Metric    int
}

func getDefaultRouteNetlink() (*RouteInfo, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)

	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w", err)
	}

	for _, route := range routes {
		if route.Dst != nil {
			info := &RouteInfo{}

			if route.Gw != nil {
				info.Gateway = route.Gw.String()
			}

			if route.LinkIndex > 0 {
				link, err := netlink.LinkByIndex(route.LinkIndex)
				if err == nil {
					info.Interface = link.Attrs().Name
				}
			}

			if info.Gateway != "" && info.Interface != "" {
				return info, nil
			}
		}
	}

	return nil, fmt.Errorf("default route not found")
}
