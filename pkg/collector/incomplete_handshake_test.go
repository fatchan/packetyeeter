package collector

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	collectorEbpf "PacketYeeter/pkg/collector/ebpf"
	"PacketYeeter/pkg/metrics"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
)

func TestPendingHandshakeExpiredUsesThirtySecondWindow(t *testing.T) {
	nowNS := uint64(60 * time.Second)

	if pendingHandshakeExpired(nowNS, nowNS-uint64(29*time.Second)) {
		t.Fatal("handshake should still be recent at 29s")
	}
	if !pendingHandshakeExpired(nowNS, nowNS-uint64(30*time.Second)) {
		t.Fatal("handshake should be stale at 30s")
	}
}

func TestEnforceIncompleteHandshakeThresholdsIPv4DisabledThreshold(t *testing.T) {
	c := newIncompleteHandshakeUnitCollector(t)
	c.Config.IncompleteHandshakeThreshold = 0
	ip := net.ParseIP("198.51.100.10").To4()
	key := binary.LittleEndian.Uint32(ip)
	mustPutCountV4(t, c, key, 999)

	before := testutil.ToFloat64(metrics.IncompleteHandshakeBlocks)
	c.enforceIncompleteHandshakeThresholds(uint64(time.Now().UnixNano()))
	after := testutil.ToFloat64(metrics.IncompleteHandshakeBlocks)

	if got := after - before; got != 0 {
		t.Fatalf("metric delta = %v, want 0", got)
	}
	assertNotBlockedIPv4(t, c, ip)
}

func TestEnforceIncompleteHandshakeThresholdsIPv4Allowlisted(t *testing.T) {
	c := newIncompleteHandshakeUnitCollector(t)
	c.Config.IncompleteHandshakeThreshold = 5
	c.allowedNets = []*net.IPNet{mustCIDR(t, "198.51.100.0/24")}
	ip := net.ParseIP("198.51.100.10").To4()
	key := binary.LittleEndian.Uint32(ip)
	mustPutCountV4(t, c, key, 5)

	before := testutil.ToFloat64(metrics.IncompleteHandshakeBlocks)
	c.enforceIncompleteHandshakeThresholds(uint64(time.Now().UnixNano()))
	after := testutil.ToFloat64(metrics.IncompleteHandshakeBlocks)

	if got := after - before; got != 0 {
		t.Fatalf("metric delta = %v, want 0", got)
	}
	assertNotBlockedIPv4(t, c, ip)
}

func TestEnforceIncompleteHandshakeThresholdsIPv4BlocksAtThreshold(t *testing.T) {
	c := newIncompleteHandshakeUnitCollector(t)
	c.Config.IncompleteHandshakeThreshold = 5
	ip := net.ParseIP("198.51.100.10").To4()
	saddr := binary.LittleEndian.Uint32(ip)
	mustPutCountV4(t, c, saddr, 5)
	mustPutPendingV4(t, c, collectorEbpf.TcpSessionKey{Saddr: saddr, Daddr: 1, Sport: 1234, Dport: 80})
	mustPutPendingV4(t, c, collectorEbpf.TcpSessionKey{Saddr: saddr, Daddr: 2, Sport: 1235, Dport: 80})

	before := testutil.ToFloat64(metrics.IncompleteHandshakeBlocks)
	c.enforceIncompleteHandshakeThresholds(uint64(time.Now().UnixNano()))
	after := testutil.ToFloat64(metrics.IncompleteHandshakeBlocks)

	if got := after - before; got != 1 {
		t.Fatalf("metric delta = %v, want 1", got)
	}
	assertBlockedIPv4(t, c, ip)
}

func TestEnforceIncompleteHandshakeThresholdsIPv6BlocksAtThreshold(t *testing.T) {
	c := newIncompleteHandshakeUnitCollector(t)
	c.Config.IncompleteHandshakeThreshold = 3
	ip := net.ParseIP("2001:db8::1234").To16()
	var saddr [16]byte
	copy(saddr[:], ip)
	mustPutCountV6(t, c, saddr, 3)
	mustPutPendingV6(t, c, collectorEbpf.TcpSessionKeyV6{Saddr: saddr, Sport: 1234, Dport: 443})

	before := testutil.ToFloat64(metrics.IncompleteHandshakeBlocks)
	c.enforceIncompleteHandshakeThresholds(uint64(time.Now().UnixNano()))
	after := testutil.ToFloat64(metrics.IncompleteHandshakeBlocks)

	if got := after - before; got != 1 {
		t.Fatalf("metric delta = %v, want 1", got)
	}
	assertBlockedIPv6(t, c, ip)
}

func TestRemovePendingHandshakeIPv4DecrementsAndDeletesCount(t *testing.T) {
	c := newIncompleteHandshakeUnitCollector(t)
	ip := net.ParseIP("198.51.100.20").To4()
	saddr := binary.LittleEndian.Uint32(ip)
	key := collectorEbpf.TcpSessionKey{Saddr: saddr, Daddr: 10, Sport: 1234, Dport: 80}
	mustPutPendingV4(t, c, key)
	mustPutCountV4(t, c, saddr, 2)

	if err := c.removePendingHandshakeIPv4(key); err != nil {
		t.Fatalf("remove pending handshake v4: %v", err)
	}
	assertCountV4(t, c, saddr, 1)

	mustPutPendingV4(t, c, key)
	if err := c.removePendingHandshakeIPv4(key); err != nil {
		t.Fatalf("remove pending handshake v4 second time: %v", err)
	}
	assertNoCountV4(t, c, saddr)
}

func TestRemovePendingHandshakeIPv6DecrementsAndDeletesCount(t *testing.T) {
	c := newIncompleteHandshakeUnitCollector(t)
	ip := net.ParseIP("2001:db8::55").To16()
	var saddr [16]byte
	copy(saddr[:], ip)
	key := collectorEbpf.TcpSessionKeyV6{Saddr: saddr, Sport: 1234, Dport: 443}
	mustPutPendingV6(t, c, key)
	mustPutCountV6(t, c, saddr, 1)

	if err := c.removePendingHandshakeIPv6(key); err != nil {
		t.Fatalf("remove pending handshake v6: %v", err)
	}
	assertNoCountV6(t, c, saddr)
}

func newIncompleteHandshakeUnitCollector(t *testing.T) *Collector {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	blockedV4, err := cebpf.NewMap(&cebpf.MapSpec{Type: cebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 1024})
	if err != nil {
		t.Fatalf("create blocked v4 map: %v", err)
	}
	blockedV6, err := cebpf.NewMap(&cebpf.MapSpec{Type: cebpf.Hash, KeySize: 16, ValueSize: 8, MaxEntries: 1024})
	if err != nil {
		t.Fatalf("create blocked v6 map: %v", err)
	}
	pendingV4, err := cebpf.NewMap(&cebpf.MapSpec{Type: cebpf.Hash, KeySize: 12, ValueSize: 24, MaxEntries: 1024})
	if err != nil {
		t.Fatalf("create pending v4 map: %v", err)
	}
	pendingV6, err := cebpf.NewMap(&cebpf.MapSpec{Type: cebpf.Hash, KeySize: 36, ValueSize: 24, MaxEntries: 1024})
	if err != nil {
		t.Fatalf("create pending v6 map: %v", err)
	}
	countsV4, err := cebpf.NewMap(&cebpf.MapSpec{Type: cebpf.Hash, KeySize: 4, ValueSize: 16, MaxEntries: 1024})
	if err != nil {
		t.Fatalf("create count v4 map: %v", err)
	}
	countsV6, err := cebpf.NewMap(&cebpf.MapSpec{Type: cebpf.Hash, KeySize: 16, ValueSize: 16, MaxEntries: 1024})
	if err != nil {
		t.Fatalf("create count v6 map: %v", err)
	}

	t.Cleanup(func() {
		blockedV4.Close()
		blockedV6.Close()
		pendingV4.Close()
		pendingV6.Close()
		countsV4.Close()
		countsV6.Close()
	})

	return &Collector{
		Logger: logrus.New(),
		Maps: &collectorEbpf.Maps{
			BlockedIPs:                  blockedV4,
			BlockedIPsV6:                blockedV6,
			PendingHandshakes:           pendingV4,
			PendingHandshakesV6:         pendingV6,
			IncompleteHandshakeCounts:   countsV4,
			IncompleteHandshakeCountsV6: countsV6,
		},
		Config: Config{
			BlockDuration: 5 * time.Minute,
		},
	}
}

func mustPutCountV4(t *testing.T, c *Collector, key uint32, count uint32) {
	t.Helper()
	entry := collectorEbpf.IncompleteHandshakeCount{Count: count, LastUpdated: uint64(time.Now().UnixNano())}
	if err := c.Maps.IncompleteHandshakeCounts.Put(key, entry); err != nil {
		t.Fatalf("put count v4: %v", err)
	}
}

func mustPutCountV6(t *testing.T, c *Collector, key [16]byte, count uint32) {
	t.Helper()
	entry := collectorEbpf.IncompleteHandshakeCount{Count: count, LastUpdated: uint64(time.Now().UnixNano())}
	if err := c.Maps.IncompleteHandshakeCountsV6.Put(key, entry); err != nil {
		t.Fatalf("put count v6: %v", err)
	}
}

func mustPutPendingV4(t *testing.T, c *Collector, key collectorEbpf.TcpSessionKey) {
	t.Helper()
	val := collectorEbpf.HandshakeStatusGeneric{BeginTime: uint64(time.Now().UnixNano())}
	if err := c.Maps.PendingHandshakes.Put(key, val); err != nil {
		t.Fatalf("put pending v4: %v", err)
	}
}

func mustPutPendingV6(t *testing.T, c *Collector, key collectorEbpf.TcpSessionKeyV6) {
	t.Helper()
	val := collectorEbpf.HandshakeStatusGeneric{BeginTime: uint64(time.Now().UnixNano())}
	if err := c.Maps.PendingHandshakesV6.Put(key, val); err != nil {
		t.Fatalf("put pending v6: %v", err)
	}
}

func assertCountV4(t *testing.T, c *Collector, key uint32, want uint32) {
	t.Helper()
	var got collectorEbpf.IncompleteHandshakeCount
	if err := c.Maps.IncompleteHandshakeCounts.Lookup(&key, &got); err != nil {
		t.Fatalf("lookup count v4: %v", err)
	}
	if got.Count != want {
		t.Fatalf("count v4 = %d, want %d", got.Count, want)
	}
}

func assertCountV6(t *testing.T, c *Collector, key [16]byte, want uint32) {
	t.Helper()
	var got collectorEbpf.IncompleteHandshakeCount
	if err := c.Maps.IncompleteHandshakeCountsV6.Lookup(&key, &got); err != nil {
		t.Fatalf("lookup count v6: %v", err)
	}
	if got.Count != want {
		t.Fatalf("count v6 = %d, want %d", got.Count, want)
	}
}

func assertNoCountV4(t *testing.T, c *Collector, key uint32) {
	t.Helper()
	var got collectorEbpf.IncompleteHandshakeCount
	if err := c.Maps.IncompleteHandshakeCounts.Lookup(&key, &got); err == nil {
		t.Fatalf("expected no IPv4 count entry, got %d", got.Count)
	}
}

func assertNoCountV6(t *testing.T, c *Collector, key [16]byte) {
	t.Helper()
	var got collectorEbpf.IncompleteHandshakeCount
	if err := c.Maps.IncompleteHandshakeCountsV6.Lookup(&key, &got); err == nil {
		t.Fatalf("expected no IPv6 count entry, got %d", got.Count)
	}
}

func assertNoPendingForIPv4(t *testing.T, c *Collector, saddr uint32) {
	t.Helper()
	var key collectorEbpf.TcpSessionKey
	var val collectorEbpf.HandshakeStatusGeneric
	iter := c.Maps.PendingHandshakes.Iterate()
	for iter.Next(&key, &val) {
		if key.Saddr == saddr {
			t.Fatalf("expected no pending IPv4 handshakes for source %d", saddr)
		}
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterate pending v4: %v", err)
	}
}

func assertNoPendingForIPv6(t *testing.T, c *Collector, saddr [16]byte) {
	t.Helper()
	var key collectorEbpf.TcpSessionKeyV6
	var val collectorEbpf.HandshakeStatusGeneric
	iter := c.Maps.PendingHandshakesV6.Iterate()
	for iter.Next(&key, &val) {
		if key.Saddr == saddr {
			t.Fatalf("expected no pending IPv6 handshakes for source %v", saddr)
		}
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterate pending v6: %v", err)
	}
}

func assertBlockedIPv4(t *testing.T, c *Collector, ip net.IP) {
	t.Helper()
	var stored uint64
	key := binary.LittleEndian.Uint32(ip.To4())
	if err := c.Maps.BlockedIPs.Lookup(&key, &stored); err != nil {
		t.Fatalf("expected IPv4 %s to be blocked: %v", ip.String(), err)
	}
}

func assertNotBlockedIPv4(t *testing.T, c *Collector, ip net.IP) {
	t.Helper()
	var stored uint64
	key := binary.LittleEndian.Uint32(ip.To4())
	if c.Maps.BlockedIPs != nil {
		if err := c.Maps.BlockedIPs.Lookup(&key, &stored); err == nil {
			t.Fatalf("expected IPv4 %s to not be blocked", ip.String())
		}
	}
}

func assertBlockedIPv6(t *testing.T, c *Collector, ip net.IP) {
	t.Helper()
	var stored uint64
	var key [16]byte
	copy(key[:], ip.To16())
	if err := c.Maps.BlockedIPsV6.Lookup(&key, &stored); err != nil {
		t.Fatalf("expected IPv6 %s to be blocked: %v", ip.String(), err)
	}
}

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse cidr %s: %v", cidr, err)
	}
	return ipNet
}
