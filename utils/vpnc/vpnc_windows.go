package vpnc

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"sslcon/base"
	"sslcon/session"
	"sslcon/tun"
	"sslcon/utils"
)

var (
	localInterface winipcfg.LUID
	iface          winipcfg.LUID
	nextHopVPN     netip.Addr
)

func ConfigInterface(cSess *session.ConnSession) error {
	mtu, _ := tun.NativeTunDevice.MTU()
	err := SetMTU(cSess.TunName, mtu)
	if err != nil {
		return err
	}

	iface = winipcfg.LUID(tun.NativeTunDevice.LUID())

	// ip address
	iface.FlushIPAddresses(windows.AF_UNSPEC)

	nextHopVPN, _ = netip.ParseAddr(cSess.VPNAddress)
	prefixVPN, _ := netip.ParsePrefix(utils.IpMask2CIDR(cSess.VPNAddress, cSess.VPNMask))
	err = iface.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{prefixVPN})

	return err
}

func SetRoutes(cSess *session.ConnSession) error {
	// routes
	// 服务器地址可能是 IPv4 或 IPv6：host 路由前缀 IPv4 用 /32、IPv6 用 /128，并选择对应地址族的网关，
	// 否则 IPv6 目的地 + IPv4 网关会导致 Windows 返回"参数错误"
	sa := netip.MustParseAddr(cSess.ServerAddress)
	prefixLen := 32
	if sa.Is6() {
		prefixLen = 128
	}
	dst := netip.PrefixFrom(sa, prefixLen)
	err := localInterface.AddRoute(dst, physicalNextHop(dst), 5)
	if err != nil {
		if !strings.HasSuffix(err.Error(), "exists.") {
			return routingError(dst, err)
		}
	}

	// Windows 排除路由 metric 相对大小好像不起作用，但不影响效果
	if len(cSess.SplitInclude) == 0 {
		cSess.SplitInclude = append(cSess.SplitInclude, "0.0.0.0/0.0.0.0")
	}
	for _, ipMask := range cSess.SplitInclude {
		dst, _ = netip.ParsePrefix(utils.IpMaskToCIDR(ipMask))
		err = iface.AddRoute(dst, nextHopVPN, 6)
		if err != nil {
			if !strings.HasSuffix(err.Error(), "exists.") {
				return routingError(dst, err)
			}
		}
	}

	if len(cSess.SplitExclude) > 0 {
		for _, ipMask := range cSess.SplitExclude {
			dst, _ = netip.ParsePrefix(utils.IpMaskToCIDR(ipMask))
			err = localInterface.AddRoute(dst, physicalNextHop(dst), 5)
			if err != nil {
				if !strings.HasSuffix(err.Error(), "exists.") {
					return routingError(dst, err)
				}
			}
		}
	}

	// dns
	if len(cSess.DNS) > 0 {
		err = setDNS(cSess)
	}
	return err
}

func ResetRoutes(cSess *session.ConnSession) {
	// 与 SetRoutes 一致，按服务器地址族构造 host 路由（IPv4 /32，IPv6 /128）
	sa, _ := netip.ParseAddr(cSess.ServerAddress)
	prefixLen := 32
	if sa.Is6() {
		prefixLen = 128
	}
	dst := netip.PrefixFrom(sa, prefixLen)
	localInterface.DeleteRoute(dst, physicalNextHop(dst))

	if len(cSess.SplitExclude) > 0 {
		for _, ipMask := range cSess.SplitExclude {
			dst, _ = netip.ParsePrefix(utils.IpMaskToCIDR(ipMask))
			localInterface.DeleteRoute(dst, physicalNextHop(dst))
		}
	}

	if len(cSess.DynamicSplitExcludeDomains) > 0 {
		cSess.DynamicSplitExcludeResolved.Range(func(_, value any) bool {
			ips := value.([]string)
			for _, ip := range ips {
				dst, _ = netip.ParsePrefix(ip + "/32")
				localInterface.DeleteRoute(dst, physicalNextHop(dst))
			}

			return true
		})
	}
}

func DynamicAddIncludeRoutes(ips []string) {
	for _, ip := range ips {
		dst, _ := netip.ParsePrefix(ip + "/32")
		_ = iface.AddRoute(dst, nextHopVPN, 6)
	}
}

func DynamicAddExcludeRoutes(ips []string) {
	for _, ip := range ips {
		dst, _ := netip.ParsePrefix(ip + "/32")
		_ = localInterface.AddRoute(dst, physicalNextHop(dst), 5)
	}
}

// physicalNextHop 根据目标地址族返回物理网卡对应网关：
// IPv4 用 base.LocalInterface.Gateway，IPv6 用 base.LocalInterface.Gateway6。
// 避免"IPv6 目的地 + IPv4 网关"导致 Windows 报"参数错误"。
func physicalNextHop(dst netip.Prefix) netip.Addr {
	if dst.Addr().Is6() {
		if g, err := netip.ParseAddr(base.LocalInterface.Gateway6); err == nil {
			return g
		}
	}
	gw, _ := netip.ParseAddr(base.LocalInterface.Gateway)
	return gw
}

func GetLocalInterface() error {
	ifcs, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagIncludeGateways)
	if err != nil {
		return err
	}

	var primaryInterface *winipcfg.IPAdapterAddresses
	var virtualPrimaryInterface *winipcfg.IPAdapterAddresses
	for _, ifc := range ifcs {
		base.Debug(ifc.AdapterName(), ifc.Description(), ifc.FriendlyName(), ifc.Ipv4Metric, ifc.IfType)
		// exclude Virtual Ethernet and Loopback Adapter
		// https://git.zx2c4.com/wireguard-windows/tree/tunnel/winipcfg/types.go?h=v0.5.3#n61
		if (ifc.IfType == 6 || ifc.IfType == 71) && ifc.FirstGatewayAddress != nil {
			if primaryInterface == nil || (ifc.Ipv4Metric < primaryInterface.Ipv4Metric) {
				if !strings.Contains(ifc.Description(), "Virtual") {
					primaryInterface = ifc
				} else if virtualPrimaryInterface == nil {
					virtualPrimaryInterface = ifc
				}
			}
		}
	}

	if primaryInterface == nil {
		if virtualPrimaryInterface != nil {
			primaryInterface = virtualPrimaryInterface
		} else {
			return fmt.Errorf("unable to find a valid network interface")
		}
	}

	base.Info("GetLocalInterface:", primaryInterface.AdapterName(), primaryInterface.Description(),
		primaryInterface.FriendlyName(), primaryInterface.Ipv4Metric, primaryInterface.IfType)

	base.LocalInterface.Name = primaryInterface.FriendlyName()
	base.LocalInterface.Ip4 = primaryInterface.FirstUnicastAddress.Address.IP().String()
	base.LocalInterface.Gateway = primaryInterface.FirstGatewayAddress.Address.IP().String()
	base.LocalInterface.Mac = net.HardwareAddr(primaryInterface.PhysicalAddress()).String()

	localInterface = primaryInterface.LUID

	// 采集同一物理网卡的 IPv6 网关：服务器地址为 IPv6 时，添加服务器 host 路由需要 IPv6 网关，
	// 否则 IPv6 目的地 + IPv4 网关会导致 Windows 返回"参数错误"
	// 机器没有 IPv6 时采集失败不影响 IPv4 连接，故忽略错误
	ipv6Ifcs, err := winipcfg.GetAdaptersAddresses(windows.AF_INET6, winipcfg.GAAFlagIncludeGateways)
	if err == nil {
		for _, ifc := range ipv6Ifcs {
			if ifc.LUID == primaryInterface.LUID && ifc.FirstGatewayAddress != nil {
				base.LocalInterface.Gateway6 = ifc.FirstGatewayAddress.Address.IP().String()
				break
			}
		}
	}

	return nil
}

func SetMTU(ifname string, mtu int) error {
	cmdStr := fmt.Sprintf("netsh interface ipv4 set subinterface \"%s\" MTU=%d", ifname, mtu)
	err := execCmd([]string{cmdStr})
	return err
}

func routingError(dst netip.Prefix, err error) error {
	return fmt.Errorf("routing error: %s %s", dst.String(), err)
}

func execCmd(cmdStrs []string) error {
	for _, cmdStr := range cmdStrs {
		cmd := exec.Command("cmd", "/C", cmdStr)
		// reset env
		cmd.Env = []string{"Path=C:\\WINDOWS\\system32;C:\\WINDOWS"}
		// println(strings.Join(cmd.Env, "\n"))
		stdoutStderr, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s %s %s", err, cmd.String(), string(stdoutStderr))
		}
	}
	return nil
}

func setDNS(cSess *session.ConnSession) error {

	if len(cSess.DynamicSplitIncludeDomains) > 0 {
		DynamicAddIncludeRoutes(cSess.DNS)
	}

	var servers []netip.Addr
	for _, dns := range cSess.DNS {
		addr, _ := netip.ParseAddr(dns)
		servers = append(servers, addr)
	}

	err := iface.SetDNS(windows.AF_INET, servers, []string{})
	return err
}
