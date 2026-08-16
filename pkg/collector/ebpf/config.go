package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	// configKeyICMPThreshold is the config_map array index checked by the XDP
	// program (as `key_icmp_limit = 0` in protector.bpf.c) for IPv4 and IPv6
	// ICMP rate limiting. A value of 0 means "leave unset and let BPF use its
	// built-in fallback default".
	configKeyICMPThreshold uint32 = 0

	// configKeyMonitorMode is the config_map array index checked by the XDP
	// program (as `key_monitor = 1` in protector.bpf.c) before every enforcement
	// drop (bad flags, SYN-flood blocklist, ICMP/UDP rate limits, allowlist).
	configKeyMonitorMode uint32 = 1

	// configKeyUDPThreshold is the config_map array index checked by the XDP
	// program (as `key_udp_limit = 2` in protector.bpf.c) for IPv4 and IPv6 UDP
	// rate limiting. A value of 0 means "leave unset and let BPF use its built-in
	// fallback default".
	configKeyUDPThreshold uint32 = 2
)

// configKeyUDPFragMode is the config_map array index for fragmented UDP /
// IPv6 fragment handling (CONFIG_KEY_UDP_FRAG_MODE in protector.bpf.c).
const configKeyUDPFragMode uint32 = 3

// UDP fragment policy modes written to config_map[configKeyUDPFragMode].
const (
	// UDPFragModeRate is the default: do not hard-drop solely for
	// fragmentation; apply the normal UDP rate limit instead.
	UDPFragModeRate uint32 = 0
	// UDPFragModeDrop is the legacy unconditional drop of fragmented UDP
	// (IPv4) and IPv6 Fragment extension headers.
	UDPFragModeDrop uint32 = 1
)

// ParseUDPFragMode accepts operator-facing mode names.
func ParseUDPFragMode(s string) (uint32, error) {
	switch s {
	case "", "rate":
		return UDPFragModeRate, nil
	case "drop":
		return UDPFragModeDrop, nil
	default:
		return 0, fmt.Errorf("invalid udp-frag-mode %q (want rate|drop)", s)
	}
}

// SetUDPFragMode configures fragmented UDP / IPv6 fragment handling.
// See UDPFragModeRate and UDPFragModeDrop. No-op when ConfigMap is nil.
func (m *Maps) SetUDPFragMode(mode uint32) error {
	if mode != UDPFragModeRate && mode != UDPFragModeDrop {
		return fmt.Errorf("invalid udp frag mode %d", mode)
	}
	if m.ConfigMap == nil {
		return nil
	}
	return m.ConfigMap.Put(configKeyUDPFragMode, mode)
}

// SetMonitorMode toggles the collector's kernel-space dry-run/monitor mode.
// When enabled is true, the XDP program's `is_monitor` check causes every
// enforcement path to log/count matching traffic without ever returning
// XDP_DROP. This is independent of the analyzer's own -dry-run flag, which
// only suppresses BLOCK commands sent back to the collector over gRPC - it
// has no effect on the collector's own kernel-level detections.
//
// It is a safe no-op (not an error) when ConfigMap is nil, e.g. on
// unsupported platforms or before the collector has finished loading eBPF.
func (m *Maps) SetMonitorMode(enabled bool) error {
	m.DryRun = enabled

	if m.ConfigMap == nil {
		return nil
	}

	var value uint32
	if enabled {
		value = 1
	}

	return m.ConfigMap.Put(configKeyMonitorMode, value)
}

// SetICMPThreshold writes the kernel/XDP ICMP per-source PPS threshold into
// config_map for both IPv4 and IPv6 enforcement paths. A value of 0 is treated
// as "use the BPF program's built-in fallback default" and intentionally does
// not write anything.
func (m *Maps) SetICMPThreshold(limit uint32) error {
	if m.ConfigMap == nil || limit == 0 {
		return nil
	}
	return m.ConfigMap.Put(configKeyICMPThreshold, limit)
}

// SetUDPThreshold writes the kernel/XDP UDP per-source PPS threshold into
// config_map for both IPv4 and IPv6 enforcement paths. A value of 0 is treated
// as "use the BPF program's built-in fallback default" and intentionally does
// not write anything.
func (m *Maps) SetUDPThreshold(limit uint32) error {
	if m.ConfigMap == nil || limit == 0 {
		return nil
	}
	return m.ConfigMap.Put(configKeyUDPThreshold, limit)
}

func (m *Maps) MarkHTTP3SeenIP(ip net.IP, ttl time.Duration) error {
	expiresAt := uint64(time.Now().Add(ttl).UnixNano())

	if ip4 := ip.To4(); ip4 != nil {
		if m.HTTP3SeenIPs == nil {
			return nil
		}
		return m.HTTP3SeenIPs.Put(binary.LittleEndian.Uint32(ip4), expiresAt)
	}

	if ip16 := ip.To16(); ip16 != nil {
		if m.HTTP3SeenIPsV6 == nil {
			return nil
		}
		var key [16]byte
		copy(key[:], ip16)
		return m.HTTP3SeenIPsV6.Put(key, expiresAt)
	}

	return nil
}
