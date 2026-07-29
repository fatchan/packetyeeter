package ebpf

import (
	"encoding/binary"
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

func (m *Maps) IsHTTP3SeenIP(ip net.IP) bool {
	now := uint64(time.Now().UnixNano())

	if ip4 := ip.To4(); ip4 != nil {
		if m.HTTP3SeenIPs == nil {
			return false
		}
		key := binary.LittleEndian.Uint32(ip4)
		var expiresAt uint64
		if err := m.HTTP3SeenIPs.Lookup(key, &expiresAt); err != nil {
			return false
		}
		if expiresAt > now {
			return true
		}
		_ = m.HTTP3SeenIPs.Delete(key)
		return false
	}

	if ip16 := ip.To16(); ip16 != nil {
		if m.HTTP3SeenIPsV6 == nil {
			return false
		}
		var key [16]byte
		copy(key[:], ip16)
		var expiresAt uint64
		if err := m.HTTP3SeenIPsV6.Lookup(key, &expiresAt); err != nil {
			return false
		}
		if expiresAt > now {
			return true
		}
		_ = m.HTTP3SeenIPsV6.Delete(key)
		return false
	}

	return false
}
