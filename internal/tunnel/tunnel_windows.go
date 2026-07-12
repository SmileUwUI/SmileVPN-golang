package tunnel

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

type WindowsTunnel struct {
	iface           tun.Device
	ip              net.IP
	netmask         net.IPMask
	name            string
	running         bool
	oldGateway      string
	oldInterface    string
	oldInterfaceIdx string
	oldMetric       string
	excludeIPs      []string
}

func NewTunnel(name string, mtu int, address net.IP, netmask net.IPMask) (Tunnel, error) {
	iface, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %v", err)
	}

	return &WindowsTunnel{
		iface:   iface,
		ip:      address,
		netmask: netmask,
		name:    name,
		running: false,
	}, nil
}

func (w *WindowsTunnel) Name() string {
	return w.name
}

func (w *WindowsTunnel) MTU() int {
	mtu, err := w.iface.MTU()
	if err != nil {
		return 0
	}
	return mtu
}

func (w *WindowsTunnel) IP() net.IP {
	return w.ip
}

func (w *WindowsTunnel) Netmask() net.IPMask {
	return w.netmask
}

func (w *WindowsTunnel) Read(packet []byte) (int, error) {
	packets := [][]byte{packet}
	sizes := make([]int, 1)
	for {
		n, err := w.iface.Read(packets, sizes, 0)
		if err != nil {
			return 0, err
		}
		if n != 0 {
			break
		}
	}
	return sizes[0], nil
}

func (w *WindowsTunnel) Write(packet []byte) (int, error) {
	return w.iface.Write([][]byte{packet}, 0)
}

func (w *WindowsTunnel) SetIP(ip net.IP, netmask net.IPMask) error {
	w.ip = ip
	w.netmask = netmask
	return nil
}

func (w *WindowsTunnel) IsRunning() bool {
	return w.running
}

func (w *WindowsTunnel) Up(excludeIPs []string, setDefaultRoute, _, _ bool) error {
	if w.running {
		return nil
	}

	w.excludeIPs = excludeIPs

	w.saveDefaultRoute()

	maskStr := ipMaskToString(w.netmask)
	gateway := getGatewayIP(w.ip)

	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		"name="+w.name,
		"source=static",
		"addr="+w.ip.String(),
		"mask="+maskStr,
		"gateway="+gateway,
		"gwmetric=1")

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to assign IP: %v, output: %s", err, string(output))
	}

	cmd = exec.Command("netsh", "interface", "set", "interface",
		"name="+w.name,
		"admin=enabled")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable interface: %v", err)
	}

	defaultGateway := w.oldGateway
	if defaultGateway == "" {
		defaultGateway = w.getDefaultGateway()
	}

	for _, excludeIP := range excludeIPs {
		if err := w.addExclusionRoute(excludeIP, defaultGateway); err != nil {
			fmt.Printf("failed to add exclusion for %s: %v\n", excludeIP, err)
		}
	}

	if setDefaultRoute {
		if err := w.setDefaultRoute(); err != nil {
			return fmt.Errorf("failed to set default route: %v", err)
		}
	}

	time.Sleep(500 * time.Millisecond)
	w.running = true

	return nil
}

func (w *WindowsTunnel) saveDefaultRoute() {
	cmd := exec.Command("route", "print", "0.0.0.0")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "0.0.0.0") && strings.Contains(line, "0.0.0.0") {
			parts := strings.Fields(line)
			if len(parts) >= 5 {
				w.oldGateway = parts[2]
				w.oldInterface = parts[3]
				w.oldMetric = parts[4]
				return
			}
		}
	}
}

func (w *WindowsTunnel) getInterfaceIndexByName(name string) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		if iface.Name == name {
			return fmt.Sprintf("%d", iface.Index), nil
		}
	}

	return "", fmt.Errorf("interface %s not found", name)
}

func (w *WindowsTunnel) getInterfaceIndex() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		if iface.Name == w.name {
			return fmt.Sprintf("%d", iface.Index), nil
		}
	}

	return "", fmt.Errorf("interface %s not found", w.name)
}

func (w *WindowsTunnel) Down(deleteNAT, delDefaultRoute, clearConntrack bool) error {
	if !w.running {
		return nil
	}

	if delDefaultRoute {
		exec.Command("route", "delete", "0.0.0.0").Run()
	}

	w.restoreDefaultRoute()

	for _, excludeIP := range w.excludeIPs {
		w.removeExclusionRoute(excludeIP)
	}

	w.running = false
	return nil
}

func (w *WindowsTunnel) restoreDefaultRoute() {
	if w.oldGateway == "" {
		return
	}

	exec.Command("route", "delete", "0.0.0.0").Run()

	if w.oldInterface != "" {
		cmd := exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0",
			w.oldGateway, "metric", w.oldMetric)
		cmd.Run()
	}
}

func (w *WindowsTunnel) Close(deleteNAT, delDefaultRoute, clearConntrack bool) error {
	if err := w.Down(deleteNAT, delDefaultRoute, clearConntrack); err != nil {
		return err
	}

	if w.iface != nil {
		return w.iface.Close()
	}
	return nil
}

func ipMaskToString(mask net.IPMask) string {
	if len(mask) == 0 {
		return "255.255.255.0"
	}
	parts := make([]string, len(mask))
	for i, b := range mask {
		parts[i] = fmt.Sprintf("%d", b)
	}
	return strings.Join(parts, ".")
}

func getGatewayIP(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 != nil {
		gateway := net.IPv4(ip4[0], ip4[1], ip4[2], 1)
		return gateway.String()
	}
	return ip.String()
}

func (w *WindowsTunnel) getDefaultGateway() string {
	if w.oldGateway != "" {
		return w.oldGateway
	}

	cmd := exec.Command("route", "print", "0.0.0.0")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "0.0.0.0") && strings.Contains(line, "0.0.0.0") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				return parts[2]
			}
		}
	}
	return ""
}

func (w *WindowsTunnel) addExclusionRoute(excludeIP, gateway string) error {
	ifIndex, err := w.getInterfaceIndex()
	if err != nil {
		return err
	}

	if gateway == "" {
		gateway = w.getDefaultGateway()
		if gateway == "" {
			gateway = "192.168.0.1"
		}
	}

	cmd := exec.Command("netsh", "interface", "ip", "add", "route",
		"prefix="+excludeIP+"/32",
		"interface="+ifIndex,
		"nexthop="+gateway,
		"metric=1",
		"store=active")

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add exclusion route: %v, output: %s", err, string(output))
	}

	return nil
}

func (w *WindowsTunnel) removeExclusionRoute(excludeIP string) {
	cmd := exec.Command("netsh", "interface", "ip", "delete", "route",
		"prefix="+excludeIP+"/32")
	cmd.Run()
}

func (w *WindowsTunnel) setDefaultRoute() error {
	ifIndex, err := w.getInterfaceIndex()
	if err != nil {
		return err
	}

	gateway := getGatewayIP(w.ip)

	exec.Command("route", "delete", "0.0.0.0").Run()

	cmd := exec.Command("netsh", "interface", "ip", "add", "route",
		"0.0.0.0/0",
		"interface="+ifIndex,
		"nexthop="+gateway,
		"metric=1",
		"store=active")

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set default route: %v, output: %s", err, string(output))
	}

	return nil
}
