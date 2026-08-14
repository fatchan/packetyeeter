package ebpf

import (
	"net"

	"github.com/cilium/ebpf"
)

type Maps struct {
	BlockedIPs                   *ebpf.Map
	BlockedIPsV6                 *ebpf.Map
	PendingHandshakes            *ebpf.Map
	PendingHandshakesV6          *ebpf.Map
	IncompleteHandshakeCounts    *ebpf.Map
	IncompleteHandshakeCountsV6  *ebpf.Map
	ICMPRates                    *ebpf.Map
	ICMPRatesV6                  *ebpf.Map
	BadFlags                     *ebpf.Map
	BadFlagsV6                   *ebpf.Map
	ConfigMap                    *ebpf.Map
	UDPRates                     *ebpf.Map
	UDPRatesV6                   *ebpf.Map
	HTTP3SeenIPs                 *ebpf.Map
	HTTP3SeenIPsV6               *ebpf.Map
	AllowListV4                  *ebpf.Map
	AllowListV6                  *ebpf.Map
	Events                       *ebpf.Map // Perf Event Array
	Incidents                    *ebpf.Map // Structured incident logging perf event array
	IncidentDropCounts *ebpf.Map
	AllowedNets        []*net.IPNet // Userspace check
	DryRun             bool
}
