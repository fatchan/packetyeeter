package collector

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func newBenchmarkCollector() *Collector {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.WarnLevel)

	return &Collector{
		Logger:           logger,
		incidentLogState: make(map[string]*incidentLogThrottleState),
	}
}

func benchmarkAlwaysLog(b *testing.B, reasonFn func(int) string) {
	c := newBenchmarkCollector()
	ip := net.ParseIP("192.0.2.10")
	kernelTimestamp := uint64(123456789)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		reason := reasonFn(i)
		c.Logger.WithFields(logrus.Fields{
			"ip":               ip.String(),
			"reason":           reason,
			"kernel_timestamp": kernelTimestamp,
		}).Warn("Kernel-space enforcement incident")
	}
}

func benchmarkThrottledLog(b *testing.B, reasonFn func(int) string) {
	c := newBenchmarkCollector()
	ip := net.ParseIP("192.0.2.10")
	kernelTimestamp := uint64(123456789)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.logIncidentThrottled(ip, reasonFn(i), kernelTimestamp)
	}
}

func BenchmarkAlwaysLogSameReason(b *testing.B) {
	benchmarkAlwaysLog(b, func(int) string { return "udp_rate" })
}

func BenchmarkThrottledLogSameReason(b *testing.B) {
	benchmarkThrottledLog(b, func(int) string { return "udp_rate" })
}

func BenchmarkAlwaysLogManyReasons(b *testing.B) {
	reasons := []string{"udp_rate", "icmp_rate", "blocked_ip", "bad_flags", "udp_frag", "malformed"}
	benchmarkAlwaysLog(b, func(i int) string { return reasons[i%len(reasons)] })
}

func BenchmarkThrottledLogManyReasons(b *testing.B) {
	reasons := []string{"udp_rate", "icmp_rate", "blocked_ip", "bad_flags", "udp_frag", "malformed"}
	benchmarkThrottledLog(b, func(i int) string { return reasons[i%len(reasons)] })
}

func BenchmarkThrottledLogWindowForcedEmit(b *testing.B) {
	c := newBenchmarkCollector()
	ip := net.ParseIP("192.0.2.10")
	kernelTimestamp := uint64(123456789)
	reason := "udp_rate"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.incidentLogMu.Lock()
		state, ok := c.incidentLogState[reason]
		if !ok {
			state = &incidentLogThrottleState{}
			c.incidentLogState[reason] = state
		}
		state.lastLog = time.Now().Add(-incidentLogThrottleInterval)
		c.incidentLogMu.Unlock()

		c.logIncidentThrottled(ip, reason, kernelTimestamp)
	}
}
