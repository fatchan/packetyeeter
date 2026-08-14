//go:build linux

package ebpf

import (
	"bytes"
	"embed"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:embed c/protector.bpf.*
var bpfFS embed.FS

type tcAttachment struct {
	ifaceName      string
	ifaceIndex     int
	ingressFilter  *netlink.BpfFilter
	egressFilter   *netlink.BpfFilter
}

type Loader struct {
	coll       *ebpf.Collection
	maps       *Maps
	links      []link.Link
	interfaces []string
	tcFilters  []tcAttachment
}

func normalizeInterfaces(interfaces []string) []string {
	seen := make(map[string]struct{}, len(interfaces))
	out := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		iface = strings.TrimSpace(iface)
		if iface == "" {
			continue
		}
		if _, ok := seen[iface]; ok {
			continue
		}
		seen[iface] = struct{}{}
		out = append(out, iface)
	}
	return out
}

func NewLoader(interfaces []string) *Loader {
	return &Loader{
		interfaces: normalizeInterfaces(interfaces),
	}
}

func (l *Loader) Load() error {
	bpfObj, err := bpfFS.ReadFile("c/protector.bpf.o")
	if err != nil {
		return fmt.Errorf("failed to read embedded BPF object: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObj))
	if err != nil {
		return fmt.Errorf("failed to load BPF spec: %w", err)
	}

	l.coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create BPF collection: %v", err)
	}

	l.maps = &Maps{
		BlockedIPs:                  l.coll.Maps["blocked_ips"],
		BlockedIPsV6:                l.coll.Maps["blocked_ips_v6"],
		PendingHandshakes:           l.coll.Maps["pending_handshakes"],
		PendingHandshakesV6:         l.coll.Maps["pending_handshakes_v6"],
		IncompleteHandshakeCounts:   l.coll.Maps["incomplete_handshake_counts"],
		IncompleteHandshakeCountsV6: l.coll.Maps["incomplete_handshake_counts_v6"],
		ICMPRates:                   l.coll.Maps["icmp_rates"],
		ICMPRatesV6:                 l.coll.Maps["icmp_rates_v6"],
		BadFlags:                    l.coll.Maps["bad_flags"],
		BadFlagsV6:                  l.coll.Maps["bad_flags_v6"],
		ConfigMap:                   l.coll.Maps["config_map"],
		UDPRates:                    l.coll.Maps["udp_rates"],
		UDPRatesV6:                  l.coll.Maps["udp_rates_v6"],
		HTTP3SeenIPs:                l.coll.Maps["http3_seen_ips"],
		HTTP3SeenIPsV6:              l.coll.Maps["http3_seen_ips_v6"],
		AllowListV4:                 l.coll.Maps["allowlist_v4"],
		AllowListV6:                 l.coll.Maps["allowlist_v6"],
		PolicyBlocks:                l.coll.Maps["policy_blocks"],
		PolicyBlocksV6:              l.coll.Maps["policy_blocks_v6"],
		Events:                      l.coll.Maps["events"],
		Incidents:                   l.coll.Maps["incidents"],
		IncidentDropCounts:          l.coll.Maps["incident_drop_counts"],
		EgressBytes:                 l.coll.Maps["egress_bytes"],
		EgressBytesV6:               l.coll.Maps["egress_bytes_v6"],
	}

	return nil
}

func (l *Loader) Attach() error {
	if len(l.interfaces) == 0 {
		return fmt.Errorf("no interfaces configured")
	}

	xdpProg := l.coll.Programs["xdp_filter"]
	ingressProg := l.coll.Programs["tc_ingress_syn_monitor"]
	egressProg := l.coll.Programs["tc_egress_synack_monitor"]

	for _, ifaceName := range l.interfaces {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			l.closeAttachments()
			return fmt.Errorf("interface %s not found: %w", ifaceName, err)
		}

		xdpLink, err := link.AttachXDP(link.XDPOptions{
			Program:   xdpProg,
			Interface: iface.Index,
		})
		if err != nil {
			l.closeAttachments()
			return fmt.Errorf("failed to attach XDP to %s: %w", ifaceName, err)
		}
		l.links = append(l.links, xdpLink)

		qdisc := &netlink.GenericQdisc{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: iface.Index,
				Handle:    netlink.MakeHandle(0xffff, 0),
				Parent:    netlink.HANDLE_CLSACT,
			},
			QdiscType: "clsact",
		}
		netlink.QdiscAdd(qdisc)

		attachment := tcAttachment{
			ifaceName:  ifaceName,
			ifaceIndex: iface.Index,
		}

		attachment.ingressFilter = &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: iface.Index,
				Parent:    netlink.MakeHandle(0xffff, 0xfff2),
				Protocol:  unix.ETH_P_ALL,
				Priority:  1,
			},
			Fd:           ingressProg.FD(),
			Name:         "tc_ingress_syn_monitor",
			DirectAction: true,
		}
		if err := netlink.FilterAdd(attachment.ingressFilter); err != nil {
			xdpLink.Close()
			l.links = l.links[:len(l.links)-1]
			l.closeAttachments()
			return fmt.Errorf("failed to attach TC Ingress to %s: %w", ifaceName, err)
		}

		attachment.egressFilter = &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: iface.Index,
				Parent:    netlink.MakeHandle(0xffff, 0xfff3),
				Protocol:  unix.ETH_P_ALL,
				Priority:  1,
			},
			Fd:           egressProg.FD(),
			Name:         "tc_egress_synack_monitor",
			DirectAction: true,
		}
		if err := netlink.FilterAdd(attachment.egressFilter); err != nil {
			netlink.FilterDel(attachment.ingressFilter)
			xdpLink.Close()
			l.links = l.links[:len(l.links)-1]
			l.closeAttachments()
			return fmt.Errorf("failed to attach TC Egress to %s: %w", ifaceName, err)
		}

		l.tcFilters = append(l.tcFilters, attachment)
	}

	return nil
}

func (l *Loader) closeAttachments() {
	for i := len(l.tcFilters) - 1; i >= 0; i-- {
		if l.tcFilters[i].ingressFilter != nil {
			netlink.FilterDel(l.tcFilters[i].ingressFilter)
		}
		if l.tcFilters[i].egressFilter != nil {
			netlink.FilterDel(l.tcFilters[i].egressFilter)
		}
	}
	l.tcFilters = nil
	for i := len(l.links) - 1; i >= 0; i-- {
		l.links[i].Close()
	}
	l.links = nil
}

func (l *Loader) Close() {
	l.closeAttachments()
	if l.coll != nil {
		l.coll.Close()
	}
}

func (l *Loader) GetMaps() *Maps {
	return l.maps
}
