package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"PacketYeeter/pkg/collector/ebpf"
	"PacketYeeter/pkg/collector/haproxy"
	"PacketYeeter/pkg/geoip"
	"PacketYeeter/pkg/metrics"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const incompleteHandshakeBlockReason = "Incomplete Handshake Flood"

// Config holds collector configuration
type Config struct {
	Interface                    string
	Interfaces                   []string
	MetricsAddr                  string
	HAProxyPort                  int
	SocketPath                   string
	GeoIPASNPath                 string
	DynamicAllowlistSocketPath   string
	DynamicAllowlistInterval     time.Duration
	HAProxyWhitelistMapPath      string
	HAProxyBackendsMapPath       string
	BlockDuration                time.Duration
	PollInterval                 time.Duration
	ICMPThreshold                uint32
	UDPThreshold                 uint32
	IncompleteHandshakeThreshold uint32
	HTTP3SeenTTL                 time.Duration
	VerboseMapEntryUpdates       bool
	DryRun                       bool
	UDPFragMode                  uint32
}

// Collector is a collector-only enforcement daemon that:
// 1. Loads eBPF programs and exposes maps
// 2. Executes local block/unblock/allowlist operations
// 3. Exposes metrics, management, and HAProxy peer integrations
type prevRate struct {
	lastTime uint64
	count    uint64
}

type incidentLogThrottleState struct {
	lastLog    time.Time
	suppressed uint64
}

type Collector struct {
	Config Config

	// Components
	Loader             *ebpf.Loader
	Maps               *ebpf.Maps
	GeoIP              *geoip.Provider
	Logger             *logrus.Logger
	allowedNets        []*net.IPNet
	dynamicAllowedNets map[string]*net.IPNet
	allowlistMu        sync.RWMutex
	incidentReader     *perf.Reader

	// Previous rates to compute pps across windows (monotonic timestamps)
	prevICMPRates   map[uint32]prevRate
	prevUDPRates    map[uint32]prevRate
	prevICMPRatesV6 map[[16]byte]prevRate
	prevUDPRatesV6  map[[16]byte]prevRate

	// Previous absolute exact-drop totals read from the BPF per-reason counter
	// map. Prometheus counters must only move forward, so we diff successive
	// absolute reads and add only the positive delta.
	prevIncidentDropCounts map[uint32]uint64

	// Last-alerted timestamps for bad TCP flag scans so repeated polls can log
	// only newly observed kernel events.
	prevBadFlagsSeen   map[uint32]uint64
	prevBadFlagsSeenV6 map[[16]byte]uint64

	// Aggregate high-volume incident logs by reason to keep logging cheap
	// while preserving exact Prometheus counters.
	incidentLogMu    sync.Mutex
	incidentLogState map[string]*incidentLogThrottleState

	// HAProxy peer listener
	haproxyPeerServer *haproxy.Server

	// Metrics server
	metricsServer *http.Server

	// Management API
	managementListener net.Listener

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func normalizeInterfaces(primary string, interfaces []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(interfaces)+1)
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
	for _, iface := range strings.Split(primary, ",") {
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

func New(cfg Config, logger *logrus.Logger) (*Collector, error) {
	cfg.Interfaces = normalizeInterfaces(cfg.Interface, cfg.Interfaces)
	if len(cfg.Interfaces) == 0 {
		return nil, fmt.Errorf("no interfaces configured")
	}

	c := &Collector{
		Config:                 cfg,
		Logger:                 logger,
		prevICMPRates:          make(map[uint32]prevRate),
		prevUDPRates:           make(map[uint32]prevRate),
		prevICMPRatesV6:        make(map[[16]byte]prevRate),
		prevUDPRatesV6:         make(map[[16]byte]prevRate),
		prevIncidentDropCounts: make(map[uint32]uint64),
		prevBadFlagsSeen:       make(map[uint32]uint64),
		prevBadFlagsSeenV6:     make(map[[16]byte]uint64),
		dynamicAllowedNets:     make(map[string]*net.IPNet),
		incidentLogState:       make(map[string]*incidentLogThrottleState),
	}

	if cfg.GeoIPASNPath != "" {
		geoIPProvider, err := geoip.New(cfg.GeoIPASNPath, "")
		if err != nil {
			logger.WithError(err).Warn("Failed to load GeoIP database")
		} else {
			c.GeoIP = geoIPProvider
		}
	}

	return c, nil
}

func (c *Collector) Start(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)

	c.checkKernelSynCookies()

	c.Logger.WithField("interfaces", c.Config.Interfaces).Info("Loading eBPF programs...")
	c.Loader = ebpf.NewLoader(c.Config.Interfaces)
	if err := c.Loader.Load(); err != nil {
		return fmt.Errorf("failed to load eBPF: %w", err)
	}
	if err := c.Loader.Attach(); err != nil {
		return fmt.Errorf("failed to attach eBPF: %w", err)
	}
	c.Maps = c.Loader.GetMaps()
	c.Logger.WithField("interfaces", c.Config.Interfaces).Info("eBPF programs loaded and attached")

	if err := c.Maps.SetICMPThreshold(c.Config.ICMPThreshold); err != nil {
		c.Logger.WithError(err).Warn("Failed to configure kernel/XDP ICMP threshold; BPF default may still apply")
	} else if c.Config.ICMPThreshold > 0 {
		c.Logger.WithField("threshold_pps", c.Config.ICMPThreshold).Info("Configured kernel/XDP ICMP threshold")
	}

	if err := c.Maps.SetUDPThreshold(c.Config.UDPThreshold); err != nil {
		c.Logger.WithError(err).Warn("Failed to configure kernel/XDP UDP threshold; BPF default may still apply")
	} else if c.Config.UDPThreshold > 0 {
		c.Logger.WithField("threshold_pps", c.Config.UDPThreshold).Info("Configured kernel/XDP UDP threshold")
	}

	if c.Config.DryRun {
		if err := c.Maps.SetMonitorMode(true); err != nil {
			c.Logger.WithError(err).Warn("Failed to enable kernel-space monitor mode; enforcement may still drop traffic")
		} else {
			c.Logger.Warn("Collector running in DRY-RUN / monitor mode: kernel-space detections will log but not drop traffic")
		}
	}

	fragMode := c.Config.UDPFragMode
	if fragMode != ebpf.UDPFragModeRate && fragMode != ebpf.UDPFragModeDrop {
		fragMode = ebpf.UDPFragModeRate
	}
	if err := c.Maps.SetUDPFragMode(fragMode); err != nil {
		c.Logger.WithError(err).Warn("Failed to set UDP fragment mode; kernel default applies")
	} else {
		modeName := "rate"
		if fragMode == ebpf.UDPFragModeDrop {
			modeName = "drop"
		}
		c.Logger.WithField("udp_frag_mode", modeName).Info("UDP fragment policy configured")
	}

	if len(c.allowedNets) > 0 {
		if err := c.Maps.SyncAllowlist(c.allowedNets); err != nil {
			c.Logger.WithError(err).Warn("Failed to fully populate kernel-space allowlist maps")
		}
	}

	if c.Config.SocketPath != "" {
		if err := c.startManagementSocket(); err != nil {
			return fmt.Errorf("failed to start management socket: %w", err)
		}
	}

	if err := c.startIncidentReader(); err != nil {
		c.Logger.WithError(err).Warn("Failed to start incident event reader, structured incident logging will be unavailable")
	}

	if c.Config.HAProxyPort > 0 {
		c.haproxyPeerServer = haproxy.NewServer(c.Config.HAProxyPort, c.Maps, c.Config.HTTP3SeenTTL, c.Config.VerboseMapEntryUpdates)
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			if err := c.haproxyPeerServer.Start(); err != nil {
				if c.ctx.Err() == nil {
					c.Logger.WithError(err).Error("HAProxy peer listener error")
				}
			}
		}()
	}

	if c.Config.DynamicAllowlistSocketPath != "" {
		c.Logger.WithFields(logrus.Fields{
			"socket_path":        c.Config.DynamicAllowlistSocketPath,
			"interval":           c.Config.DynamicAllowlistInterval,
			"whitelist_map_path": c.Config.HAProxyWhitelistMapPath,
			"backends_map_path":  c.Config.HAProxyBackendsMapPath,
		}).Info("Dynamic allowlist syncing enabled")
		c.wg.Add(1)
		go c.runDynamicAllowlistSync()
	}

	c.wg.Add(1)
	go c.pollMaps()

	c.wg.Add(1)
	go c.runBlockGC()

	c.metricsServer = c.startCollectorMetricsServer()
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.Logger.WithField("addr", c.Config.MetricsAddr).Info("Starting collector metrics server")
		if err := c.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			c.Logger.WithError(err).Error("Metrics server error")
		}
	}()

	c.Logger.WithFields(logrus.Fields{
		"interfaces":                     c.Config.Interfaces,
		"http3_seen_ttl":                 c.Config.HTTP3SeenTTL,
		"verbose_map_entry_updates":      c.Config.VerboseMapEntryUpdates,
		"incomplete_handshake_threshold": c.Config.IncompleteHandshakeThreshold,
	}).Info("Collector-only mode active")

	c.Logger.Info("Collector started")
	return nil
}

func (c *Collector) checkAllowlist(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}
	c.allowlistMu.RLock()
	defer c.allowlistMu.RUnlock()
	for _, subnet := range c.allowedNets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *Collector) Stop() {
	c.Logger.Info("Stopping collector...")
	if c.cancel != nil {
		c.cancel()
	}

	if c.haproxyPeerServer != nil {
		if err := c.haproxyPeerServer.Stop(); err != nil {
			c.Logger.WithError(err).Warn("HAProxy peer listener shutdown error")
		}
	}

	c.stopManagementSocket()

	if c.incidentReader != nil {
		c.incidentReader.Close()
	}

	if c.metricsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.metricsServer.Shutdown(ctx); err != nil {
			c.Logger.WithError(err).Warn("Metrics server shutdown error")
		}
	}

	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		c.Logger.Info("Collector stopped gracefully")
	case <-time.After(10 * time.Second):
		c.Logger.Warn("Shutdown timeout waiting for goroutines")
	}

	if c.Loader != nil {
		c.Loader.Close()
	}
	if c.GeoIP != nil {
		c.GeoIP.Close()
	}
}

func (c *Collector) pollMaps() {
	defer c.wg.Done()

	interval := c.Config.PollInterval
	if interval == 0 {
		interval = time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	c.Logger.WithField("interval", interval).Info("Starting eBPF map poller")

	lastKernelStateGC := time.Time{}

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.Logger.Debug("Polling eBPF maps for local maintenance")
			c.syncIncidentDropCounters()
			c.refreshPendingHandshakes()
			c.refreshICMPRates()
			c.refreshUDPRates()
			c.refreshBadFlags()
			c.pruneStaleState()
			if lastKernelStateGC.IsZero() || time.Since(lastKernelStateGC) >= kernelStateCleanupInterval {
				c.cleanupStaleKernelState()
				lastKernelStateGC = time.Now()
			}
		}
	}
}

func (c *Collector) startIncidentReader() error {
	if c.Maps == nil || c.Maps.Incidents == nil {
		return fmt.Errorf("incidents map not available")
	}

	reader, err := perf.NewReader(c.Maps.Incidents, 4096*16)
	if err != nil {
		return fmt.Errorf("failed to create incident perf reader: %w", err)
	}

	c.incidentReader = reader
	c.wg.Add(1)
	go c.readIncidentEvents()

	c.Logger.Info("Started perf event reader for structured incident logging")
	return nil
}

func (c *Collector) readIncidentEvents() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		record, err := c.incidentReader.Read()
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			c.Logger.WithError(err).Debug("Error reading incident event")
			continue
		}
		c.recordPerfLostSamples("incidents", record.LostSamples)

		c.processIncidentEvent(record.RawSample)
	}
}

func (c *Collector) recordPerfLostSamples(reader string, lost uint64) {
	if lost == 0 {
		return
	}
	metrics.PerfLostSamples.WithLabelValues(reader).Add(float64(lost))
	c.Logger.WithFields(logrus.Fields{
		"reader":       reader,
		"lost_samples": lost,
	}).Warn("Kernel perf-ring samples lost")
}

const incidentLogThrottleInterval = 5 * time.Second

func (c *Collector) logIncidentThrottled(ip net.IP, reason string, kernelTimestamp uint64) {
	key := reason
	now := time.Now()

	c.incidentLogMu.Lock()
	state, ok := c.incidentLogState[key]
	if !ok {
		state = &incidentLogThrottleState{}
		c.incidentLogState[key] = state
	}

	if state.lastLog.IsZero() || now.Sub(state.lastLog) >= incidentLogThrottleInterval {
		suppressed := state.suppressed
		state.lastLog = now
		state.suppressed = 0
		c.incidentLogMu.Unlock()

		c.Logger.WithFields(logrus.Fields{
			"ip":               ip.String(),
			"reason":           reason,
			"kernel_timestamp": kernelTimestamp,
			"suppressed_count": suppressed,
		}).Warn("Kernel-space enforcement incident")
		return
	}

	state.suppressed++
	c.incidentLogMu.Unlock()
}

func (c *Collector) processIncidentEvent(data []byte) {
	var inc ebpf.IncidentEvent
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &inc); err != nil {
		c.Logger.WithError(err).Debug("Failed to parse incident event")
		return
	}

	var ip net.IP
	if inc.IsV6 == 1 {
		ip = net.IP(inc.SaddrV6[:])
	} else {
		ipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBytes, inc.SaddrV4)
		ip = net.IP(ipBytes)
	}

	reason := ebpf.IncidentReasonName(inc.Reason)
	metrics.KernelIncidents.WithLabelValues(reason).Inc()

	c.logIncidentThrottled(ip, reason, inc.Timestamp)
}

func (c *Collector) syncIncidentDropCounters() {
	if c.Maps == nil || c.Maps.IncidentDropCounts == nil {
		return
	}

	for reason := uint32(1); reason < uint32(ebpf.IncidentMax); reason++ {
		total, err := readPerCPUCounter(c.Maps.IncidentDropCounts, reason)
		if err != nil {
			c.Logger.WithError(err).WithField("reason", reason).Debug("Failed reading exact incident drop counter")
			continue
		}

		prev := c.prevIncidentDropCounts[reason]
		if total >= prev {
			delta := total - prev
			if delta > 0 {
				metrics.KernelDroppedPacketsExact.WithLabelValues(ebpf.IncidentReasonName(uint8(reason))).Add(float64(delta))
			}
		}
		c.prevIncidentDropCounts[reason] = total
	}
}

func readPerCPUCounter(m *cebpf.Map, key uint32) (uint64, error) {
	var values []uint64
	if err := m.Lookup(&key, &values); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range values {
		total += v
	}
	return total, nil
}

// pendingHandshakeTimeout is the collector-side recentness window for deciding
// whether a handshake is still incomplete enough to matter. A source must reach
// the configured threshold within this rolling recent window before the
// collector-side incomplete-handshake autoblock path will fire.
const pendingHandshakeTimeout = 30 * time.Second

func monotonicNowNS() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	if ts.Sec < 0 || ts.Nsec < 0 {
		return 0, fmt.Errorf("invalid monotonic timestamp: %d.%09d", ts.Sec, ts.Nsec)
	}
	return uint64(ts.Sec)*uint64(time.Second) + uint64(ts.Nsec), nil
}

func pendingHandshakeExpired(nowNS, beginNS uint64) bool {
	if beginNS == 0 || nowNS < beginNS {
		return false
	}
	return nowNS-beginNS >= uint64(pendingHandshakeTimeout)
}

func (c *Collector) refreshPendingHandshakes() {
	if c.Maps == nil {
		return
	}

	nowNS, err := monotonicNowNS()
	if err != nil {
		c.Logger.WithError(err).Error("Failed to read monotonic clock for pending handshakes")
		return
	}

	if c.Maps.PendingHandshakes != nil {
		var key ebpf.TcpSessionKey
		var val ebpf.HandshakeStatusGeneric
		iter := c.Maps.PendingHandshakes.Iterate()
		for iter.Next(&key, &val) {
			// Stale entries are removed first so the block threshold applies only to
			// recent incomplete handshakes, not to long-dead residual state.
			if pendingHandshakeExpired(nowNS, val.BeginTime) {
				if err := c.removePendingHandshakeIPv4(key); err != nil {
					c.Logger.WithError(err).Debug("Failed to prune expired IPv4 pending handshake")
				}
				continue
			}
		}
		if err := iter.Err(); err != nil {
			c.Logger.WithError(err).Warn("Failed to iterate IPv4 pending handshakes")
		}
	}

	if c.Maps.PendingHandshakesV6 != nil {
		var key ebpf.TcpSessionKeyV6
		var val ebpf.HandshakeStatusGeneric
		iter := c.Maps.PendingHandshakesV6.Iterate()
		for iter.Next(&key, &val) {
			// Same logic as IPv4: only recent incomplete handshakes should count
			// toward autoblocking, and stale entries should be removed opportunistically.
			if pendingHandshakeExpired(nowNS, val.BeginTime) {
				if err := c.removePendingHandshakeIPv6(key); err != nil {
					c.Logger.WithError(err).Debug("Failed to prune expired IPv6 pending handshake")
				}
				continue
			}
		}
		if err := iter.Err(); err != nil {
			c.Logger.WithError(err).Warn("Failed to iterate IPv6 pending handshakes")
		}
	}

	c.enforceIncompleteHandshakeThresholds(nowNS)
}

func (c *Collector) enforceIncompleteHandshakeThresholds(nowNS uint64) {
	if c.Config.IncompleteHandshakeThreshold == 0 || c.Maps == nil {
		return
	}
	c.enforceIncompleteHandshakeThresholdsIPv4(nowNS)
	c.enforceIncompleteHandshakeThresholdsIPv6(nowNS)
}

func (c *Collector) enforceIncompleteHandshakeThresholdsIPv4(nowNS uint64) {
	if c.Maps.IncompleteHandshakeCounts == nil {
		return
	}
	cutoffNS := staleKernelCutoff(nowNS, kernelStateExpiryHandshake)
	var key uint32
	var entry ebpf.IncompleteHandshakeCount
	iter := c.Maps.IncompleteHandshakeCounts.Iterate()
	for iter.Next(&key, &entry) {
		if entry.Count == 0 {
			continue
		}
		if cutoffNS != 0 && entry.LastUpdated != 0 && entry.LastUpdated < cutoffNS {
			continue
		}
		if entry.Count < c.Config.IncompleteHandshakeThreshold {
			continue
		}
		ipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBytes, key)
		ip := net.IP(ipBytes)
		if c.checkAllowlist(ip) {
			continue
		}
		if err := c.blockIncompleteHandshakeIP(ip, entry.Count); err != nil {
			c.Logger.WithError(err).WithFields(logrus.Fields{
				"ip":                         ip.String(),
				"reason":                     incompleteHandshakeBlockReason,
				"incomplete_handshake_count": entry.Count,
				"threshold":                  c.Config.IncompleteHandshakeThreshold,
				"last_updated_ns":            entry.LastUpdated,
			}).Warn("Failed to block IP for incomplete handshake flood")
			continue
		}
		if err := c.purgePendingHandshakesForIPv4(ip); err != nil {
			c.Logger.WithError(err).WithField("ip", ip.String()).Warn("Blocked IP but failed to purge IPv4 pending handshake state")
		}
	}
	if err := iter.Err(); err != nil {
		c.Logger.WithError(err).Warn("Failed to iterate IPv4 incomplete handshake counts")
	}
}

func (c *Collector) enforceIncompleteHandshakeThresholdsIPv6(nowNS uint64) {
	if c.Maps.IncompleteHandshakeCountsV6 == nil {
		return
	}
	cutoffNS := staleKernelCutoff(nowNS, kernelStateExpiryHandshake)
	var key [16]byte
	var entry ebpf.IncompleteHandshakeCount
	iter := c.Maps.IncompleteHandshakeCountsV6.Iterate()
	for iter.Next(&key, &entry) {
		if entry.Count == 0 {
			continue
		}
		if cutoffNS != 0 && entry.LastUpdated != 0 && entry.LastUpdated < cutoffNS {
			continue
		}
		if entry.Count < c.Config.IncompleteHandshakeThreshold {
			continue
		}
		ip := net.IP(key[:])
		if c.checkAllowlist(ip) {
			continue
		}
		if err := c.blockIncompleteHandshakeIP(ip, entry.Count); err != nil {
			c.Logger.WithError(err).WithFields(logrus.Fields{
				"ip":                         ip.String(),
				"reason":                     incompleteHandshakeBlockReason,
				"incomplete_handshake_count": entry.Count,
				"threshold":                  c.Config.IncompleteHandshakeThreshold,
				"last_updated_ns":            entry.LastUpdated,
			}).Warn("Failed to block IPv6 IP for incomplete handshake flood")
			continue
		}
		if err := c.purgePendingHandshakesForIPv6(ip); err != nil {
			c.Logger.WithError(err).WithField("ip", ip.String()).Warn("Blocked IPv6 IP but failed to purge pending handshake state")
		}
	}
	if err := iter.Err(); err != nil {
		c.Logger.WithError(err).Warn("Failed to iterate IPv6 incomplete handshake counts")
	}
}

func (c *Collector) blockIncompleteHandshakeIP(ip net.IP, count uint32) error {
	if err := c.Maps.BlockIP(ip, incompleteHandshakeBlockReason, logrus.Fields{
		"reason":                     incompleteHandshakeBlockReason,
		"incomplete_handshake_count": count,
		"threshold":                  c.Config.IncompleteHandshakeThreshold,
		"window":                     pendingHandshakeTimeout,
		"block_duration":             c.Config.BlockDuration,
	}); err != nil {
		return err
	}
	metrics.IncompleteHandshakeBlocks.Inc()
	c.Logger.WithFields(logrus.Fields{
		"ip":                         ip.String(),
		"reason":                     incompleteHandshakeBlockReason,
		"incomplete_handshake_count": count,
		"threshold":                  c.Config.IncompleteHandshakeThreshold,
		"window":                     pendingHandshakeTimeout,
		"block_duration":             c.Config.BlockDuration,
	}).Warn("Blocked IP due to incomplete handshake flood")
	return nil
}

func (c *Collector) removePendingHandshakeIPv4(key ebpf.TcpSessionKey) error {
	if c.Maps == nil || c.Maps.PendingHandshakes == nil {
		return nil
	}
	if err := c.Maps.PendingHandshakes.Delete(&key); err != nil {
		return err
	}
	return c.decrementIncompleteHandshakeCountIPv4(key.Saddr)
}

func (c *Collector) removePendingHandshakeIPv6(key ebpf.TcpSessionKeyV6) error {
	if c.Maps == nil || c.Maps.PendingHandshakesV6 == nil {
		return nil
	}
	if err := c.Maps.PendingHandshakesV6.Delete(&key); err != nil {
		return err
	}
	return c.decrementIncompleteHandshakeCountIPv6(key.Saddr)
}

func (c *Collector) decrementIncompleteHandshakeCountIPv4(saddr uint32) error {
	if c.Maps == nil || c.Maps.IncompleteHandshakeCounts == nil {
		return nil
	}
	var entry ebpf.IncompleteHandshakeCount
	if err := c.Maps.IncompleteHandshakeCounts.Lookup(&saddr, &entry); err != nil {
		return nil
	}
	if entry.Count <= 1 {
		return c.Maps.IncompleteHandshakeCounts.Delete(&saddr)
	}
	entry.Count--
	nowNS, err := monotonicNowNS()
	if err == nil {
		entry.LastUpdated = nowNS
	}
	return c.Maps.IncompleteHandshakeCounts.Put(saddr, entry)
}

func (c *Collector) decrementIncompleteHandshakeCountIPv6(saddr [16]byte) error {
	if c.Maps == nil || c.Maps.IncompleteHandshakeCountsV6 == nil {
		return nil
	}
	var entry ebpf.IncompleteHandshakeCount
	if err := c.Maps.IncompleteHandshakeCountsV6.Lookup(&saddr, &entry); err != nil {
		return nil
	}
	if entry.Count <= 1 {
		return c.Maps.IncompleteHandshakeCountsV6.Delete(&saddr)
	}
	entry.Count--
	nowNS, err := monotonicNowNS()
	if err == nil {
		entry.LastUpdated = nowNS
	}
	return c.Maps.IncompleteHandshakeCountsV6.Put(saddr, entry)
}

func (c *Collector) purgePendingHandshakesForIPv4(ip net.IP) error {
	if c.Maps == nil || c.Maps.PendingHandshakes == nil {
		return nil
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	saddr := binary.LittleEndian.Uint32(ip4)
	var key ebpf.TcpSessionKey
	var val ebpf.HandshakeStatusGeneric
	iter := c.Maps.PendingHandshakes.Iterate()
	keysToDelete := make([]ebpf.TcpSessionKey, 0)
	for iter.Next(&key, &val) {
		if key.Saddr == saddr {
			keysToDelete = append(keysToDelete, key)
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range keysToDelete {
		if err := c.Maps.PendingHandshakes.Delete(&k); err != nil {
			return err
		}
	}
	if c.Maps.IncompleteHandshakeCounts != nil {
		_ = c.Maps.IncompleteHandshakeCounts.Delete(&saddr)
	}
	return nil
}

func (c *Collector) purgePendingHandshakesForIPv6(ip net.IP) error {
	if c.Maps == nil || c.Maps.PendingHandshakesV6 == nil {
		return nil
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return nil
	}
	var saddr [16]byte
	copy(saddr[:], ip16)
	var key ebpf.TcpSessionKeyV6
	var val ebpf.HandshakeStatusGeneric
	iter := c.Maps.PendingHandshakesV6.Iterate()
	keysToDelete := make([]ebpf.TcpSessionKeyV6, 0)
	for iter.Next(&key, &val) {
		if key.Saddr == saddr {
			keysToDelete = append(keysToDelete, key)
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range keysToDelete {
		if err := c.Maps.PendingHandshakesV6.Delete(&k); err != nil {
			return err
		}
	}
	if c.Maps.IncompleteHandshakeCountsV6 != nil {
		_ = c.Maps.IncompleteHandshakeCountsV6.Delete(&saddr)
	}
	return nil
}

func (c *Collector) refreshICMPRates() {
	if c.Maps == nil {
		return
	}

	totalPPS := 0.0

	if c.Maps.ICMPRates != nil {
		var ip uint32
		var rate ebpf.ICMPRate
		iter := c.Maps.ICMPRates.Iterate()
		for iter.Next(&ip, &rate) {
			if rate.Count == 0 {
				continue
			}
			totalPPS += computePPS(c.prevICMPRates, ip, rate)
		}
	}

	if c.Maps.ICMPRatesV6 != nil {
		var key [16]byte
		var rate ebpf.ICMPRate
		iter := c.Maps.ICMPRatesV6.Iterate()
		for iter.Next(&key, &rate) {
			if rate.Count == 0 {
				continue
			}
			totalPPS += computePPSV6(c.prevICMPRatesV6, key, rate)
		}
	}

	if metrics.ICMPTotalRate != nil {
		metrics.ICMPTotalRate.Set(totalPPS)
	}
}

func (c *Collector) refreshUDPRates() {
	if c.Maps == nil {
		return
	}

	totalPPS := 0.0

	if c.Maps.UDPRates != nil {
		var ip uint32
		var rate ebpf.ICMPRate
		iter := c.Maps.UDPRates.Iterate()
		for iter.Next(&ip, &rate) {
			if rate.Count == 0 {
				continue
			}
			totalPPS += computePPS(c.prevUDPRates, ip, rate)
		}
	}

	if c.Maps.UDPRatesV6 != nil {
		var key [16]byte
		var rate ebpf.ICMPRate
		iter := c.Maps.UDPRatesV6.Iterate()
		for iter.Next(&key, &rate) {
			if rate.Count == 0 {
				continue
			}
			totalPPS += computePPSV6(c.prevUDPRatesV6, key, rate)
		}
	}

	if metrics.UDPTotalRate != nil {
		metrics.UDPTotalRate.Set(totalPPS)
	}
}

func (c *Collector) refreshBadFlags() {
	if c.Maps == nil {
		return
	}

	if c.Maps.BadFlags != nil {
		var ip uint32
		var info ebpf.BadFlagsInfo
		iter := c.Maps.BadFlags.Iterate()
		for iter.Next(&ip, &info) {
			if info.LastSeen == 0 {
				continue
			}
			if prev, ok := c.prevBadFlagsSeen[ip]; ok && info.LastSeen <= prev {
				continue
			}
			c.prevBadFlagsSeen[ip] = info.LastSeen
		}
	}

	if c.Maps.BadFlagsV6 != nil {
		type ipv6Key [16]byte
		var saddr ipv6Key
		var info ebpf.BadFlagsInfo
		iter := c.Maps.BadFlagsV6.Iterate()
		for iter.Next(&saddr, &info) {
			if info.LastSeen == 0 {
				continue
			}
			if prev, ok := c.prevBadFlagsSeenV6[saddr]; ok && info.LastSeen <= prev {
				continue
			}
			c.prevBadFlagsSeenV6[saddr] = info.LastSeen
		}
	}
}

func computePPS(prev map[uint32]prevRate, ip uint32, rate ebpf.ICMPRate) float64 {
	if prev == nil {
		return float64(rate.Count)
	}
	pr, ok := prev[ip]
	prev[ip] = prevRate{lastTime: rate.LastTime, count: rate.Count}
	return ppsFromWindow(pr, ok, rate)
}

func computePPSV6(prev map[[16]byte]prevRate, ip [16]byte, rate ebpf.ICMPRate) float64 {
	if prev == nil {
		return float64(rate.Count)
	}
	pr, ok := prev[ip]
	prev[ip] = prevRate{lastTime: rate.LastTime, count: rate.Count}
	return ppsFromWindow(pr, ok, rate)
}

func ppsFromWindow(pr prevRate, ok bool, rate ebpf.ICMPRate) float64 {
	if !ok {
		return float64(rate.Count)
	}
	if rate.LastTime == pr.lastTime {
		return float64(rate.Count)
	}
	if rate.LastTime > pr.lastTime && rate.Count < pr.count {
		return float64(pr.count)
	}
	return float64(rate.Count)
}

func ipNetFromIP(ip net.IP) *net.IPNet {
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

const (
	prevStateStaleWindowNs     uint64        = 300 * 1_000_000_000
	prevStateHardCap                         = 1 << 18
	kernelStateExpiryRate      time.Duration = 10 * time.Minute
	kernelStateExpiryBadFlags  time.Duration = 10 * time.Minute
	kernelStateExpiryHandshake time.Duration = 30 * time.Second
	kernelStateCleanupInterval               = 5 * time.Minute
)

func (c *Collector) pruneStaleState() {
	maxClock := uint64(0)
	for _, v := range c.prevICMPRates {
		if v.lastTime > maxClock {
			maxClock = v.lastTime
		}
	}
	for _, v := range c.prevUDPRates {
		if v.lastTime > maxClock {
			maxClock = v.lastTime
		}
	}
	for _, v := range c.prevICMPRatesV6 {
		if v.lastTime > maxClock {
			maxClock = v.lastTime
		}
	}
	for _, v := range c.prevUDPRatesV6 {
		if v.lastTime > maxClock {
			maxClock = v.lastTime
		}
	}
	for _, ts := range c.prevBadFlagsSeen {
		if ts > maxClock {
			maxClock = ts
		}
	}
	for _, ts := range c.prevBadFlagsSeenV6 {
		if ts > maxClock {
			maxClock = ts
		}
	}

	prunePrevRateMap(c.prevICMPRates, maxClock, c.Logger)
	prunePrevRateMap(c.prevUDPRates, maxClock, c.Logger)
	prunePrevRateMapV6(c.prevICMPRatesV6, maxClock, c.Logger)
	prunePrevRateMapV6(c.prevUDPRatesV6, maxClock, c.Logger)
	prunePrevSeenMap(c.prevBadFlagsSeen, maxClock, c.Logger)
	prunePrevSeenMap(c.prevBadFlagsSeenV6, maxClock, c.Logger)
}

func prunePrevRateMap(m map[uint32]prevRate, maxClock uint64, logger *logrus.Logger) {
	if maxClock > prevStateStaleWindowNs {
		cutoff := maxClock - prevStateStaleWindowNs
		for k, v := range m {
			if v.lastTime < cutoff {
				delete(m, k)
			}
		}
	}
	if len(m) > prevStateHardCap {
		if logger != nil {
			logger.WithField("size", len(m)).Warn("prev-rate state exceeded hard cap under high cardinality; resetting")
		}
		for k := range m {
			delete(m, k)
		}
	}
}

func prunePrevRateMapV6(m map[[16]byte]prevRate, maxClock uint64, logger *logrus.Logger) {
	if maxClock > prevStateStaleWindowNs {
		cutoff := maxClock - prevStateStaleWindowNs
		for k, v := range m {
			if v.lastTime < cutoff {
				delete(m, k)
			}
		}
	}
	if len(m) > prevStateHardCap {
		if logger != nil {
			logger.WithField("size", len(m)).Warn("prev-rate v6 state exceeded hard cap under high cardinality; resetting")
		}
		for k := range m {
			delete(m, k)
		}
	}
}

func prunePrevSeenMap[K comparable](m map[K]uint64, maxClock uint64, logger *logrus.Logger) {
	if maxClock > prevStateStaleWindowNs {
		cutoff := maxClock - prevStateStaleWindowNs
		for k, ts := range m {
			if ts < cutoff {
				delete(m, k)
			}
		}
	}
	if len(m) > prevStateHardCap {
		if logger != nil {
			logger.WithField("size", len(m)).Warn("prev-seen state exceeded hard cap under high cardinality; resetting")
		}
		for k := range m {
			delete(m, k)
		}
	}
}

func (c *Collector) cleanupStaleKernelState() {
	start := time.Now()
	removedICMPv4, removedICMPv6 := 0, 0
	removedUDPv4, removedUDPv6 := 0, 0
	removedBadFlagsV4, removedBadFlagsV6 := 0, 0
	removedHandshakesV4, removedHandshakesV6 := 0, 0
	removedHandshakeCountsV4, removedHandshakeCountsV6 := 0, 0
	cleanupErr := ""

	defer func() {
		duration := time.Since(start)
		metrics.KernelStateCleanupDurationMilliseconds.Set(float64(duration.Milliseconds()))
		fields := logrus.Fields{
			"removed_total":                  removedICMPv4 + removedICMPv6 + removedUDPv4 + removedUDPv6 + removedBadFlagsV4 + removedBadFlagsV6 + removedHandshakesV4 + removedHandshakesV6 + removedHandshakeCountsV4 + removedHandshakeCountsV6,
			"icmp_v4":                        removedICMPv4,
			"icmp_v6":                        removedICMPv6,
			"udp_v4":                         removedUDPv4,
			"udp_v6":                         removedUDPv6,
			"bad_flags_v4":                   removedBadFlagsV4,
			"bad_flags_v6":                   removedBadFlagsV6,
			"pending_handshakes_v4":          removedHandshakesV4,
			"pending_handshakes_v6":          removedHandshakesV6,
			"incomplete_handshake_counts_v4": removedHandshakeCountsV4,
			"incomplete_handshake_counts_v6": removedHandshakeCountsV6,
			"rate_expiry":                    kernelStateExpiryRate,
			"bad_flags_expiry":               kernelStateExpiryBadFlags,
			"handshake_expiry":               kernelStateExpiryHandshake,
			"run_interval":                   kernelStateCleanupInterval,
			"duration":                       duration,
			"duration_milliseconds":          duration.Milliseconds(),
		}
		if cleanupErr != "" {
			fields["error"] = cleanupErr
			c.Logger.WithFields(fields).Warn("Completed stale kernel map cleanup with error")
			return
		}
		c.Logger.WithFields(fields).Info("Completed stale kernel map cleanup")
	}()

	if c.Maps == nil {
		return
	}

	nowNS, err := monotonicNowNS()
	if err != nil {
		cleanupErr = fmt.Sprintf("failed to read monotonic clock for kernel state cleanup: %v", err)
		c.Logger.WithError(err).Warn("Failed to read monotonic clock for kernel state cleanup")
		return
	}

	handshakeCutoff := staleKernelCutoff(nowNS, kernelStateExpiryHandshake)
	removedICMPv4 = pruneKernelRateMap(c.Maps.ICMPRates, staleKernelCutoff(nowNS, kernelStateExpiryRate), c.Logger, "icmp_rates")
	removedICMPv6 = pruneKernelRateMapV6(c.Maps.ICMPRatesV6, staleKernelCutoff(nowNS, kernelStateExpiryRate), c.Logger, "icmp_rates_v6")
	removedUDPv4 = pruneKernelRateMap(c.Maps.UDPRates, staleKernelCutoff(nowNS, kernelStateExpiryRate), c.Logger, "udp_rates")
	removedUDPv6 = pruneKernelRateMapV6(c.Maps.UDPRatesV6, staleKernelCutoff(nowNS, kernelStateExpiryRate), c.Logger, "udp_rates_v6")
	removedBadFlagsV4 = pruneKernelBadFlagsMap(c.Maps.BadFlags, staleKernelCutoff(nowNS, kernelStateExpiryBadFlags), c.Logger, "bad_flags")
	removedBadFlagsV6 = pruneKernelBadFlagsMapV6(c.Maps.BadFlagsV6, staleKernelCutoff(nowNS, kernelStateExpiryBadFlags), c.Logger, "bad_flags_v6")
	removedHandshakesV4 = pruneKernelPendingHandshakesMap(c.Maps.PendingHandshakes, handshakeCutoff, c.Logger, "pending_handshakes")
	removedHandshakesV6 = pruneKernelPendingHandshakesMapV6(c.Maps.PendingHandshakesV6, handshakeCutoff, c.Logger, "pending_handshakes_v6")
	removedHandshakeCountsV4 = pruneKernelIncompleteHandshakeCountMap(c.Maps.IncompleteHandshakeCounts, handshakeCutoff, c.Logger, "incomplete_handshake_counts")
	removedHandshakeCountsV6 = pruneKernelIncompleteHandshakeCountMapV6(c.Maps.IncompleteHandshakeCountsV6, handshakeCutoff, c.Logger, "incomplete_handshake_counts_v6")
}

func staleKernelCutoff(nowNS uint64, ttl time.Duration) uint64 {
	cutoffNS := uint64(ttl)
	if nowNS <= cutoffNS {
		return 0
	}
	return nowNS - cutoffNS
}

func pruneKernelRateMap(m *cebpf.Map, cutoffNS uint64, logger *logrus.Logger, mapName string) int {
	if m == nil || cutoffNS == 0 {
		return 0
	}
	var key uint32
	var val ebpf.ICMPRate
	iter := m.Iterate()
	keysToDelete := make([]uint32, 0)
	for iter.Next(&key, &val) {
		if val.LastTime != 0 && val.LastTime < cutoffNS {
			keysToDelete = append(keysToDelete, key)
		}
	}
	if err := iter.Err(); err != nil && logger != nil {
		logger.WithError(err).WithField("map", mapName).Warn("Failed to iterate kernel rate map for stale cleanup")
	}
	removed := 0
	for _, k := range keysToDelete {
		if err := m.Delete(&k); err == nil {
			removed++
		} else if logger != nil {
			logger.WithError(err).WithField("map", mapName).Debug("Failed to delete stale kernel rate entry")
		}
	}
	return removed
}

func pruneKernelRateMapV6(m *cebpf.Map, cutoffNS uint64, logger *logrus.Logger, mapName string) int {
	if m == nil || cutoffNS == 0 {
		return 0
	}
	var key [16]byte
	var val ebpf.ICMPRate
	iter := m.Iterate()
	keysToDelete := make([][16]byte, 0)
	for iter.Next(&key, &val) {
		if val.LastTime != 0 && val.LastTime < cutoffNS {
			keysToDelete = append(keysToDelete, key)
		}
	}
	if err := iter.Err(); err != nil && logger != nil {
		logger.WithError(err).WithField("map", mapName).Warn("Failed to iterate kernel rate v6 map for stale cleanup")
	}
	removed := 0
	for _, k := range keysToDelete {
		if err := m.Delete(&k); err == nil {
			removed++
		} else if logger != nil {
			logger.WithError(err).WithField("map", mapName).Debug("Failed to delete stale kernel rate v6 entry")
		}
	}
	return removed
}

func pruneKernelBadFlagsMap(m *cebpf.Map, cutoffNS uint64, logger *logrus.Logger, mapName string) int {
	if m == nil || cutoffNS == 0 {
		return 0
	}
	var key uint32
	var val ebpf.BadFlagsInfo
	iter := m.Iterate()
	keysToDelete := make([]uint32, 0)
	for iter.Next(&key, &val) {
		if val.LastSeen != 0 && val.LastSeen < cutoffNS {
			keysToDelete = append(keysToDelete, key)
		}
	}
	if err := iter.Err(); err != nil && logger != nil {
		logger.WithError(err).WithField("map", mapName).Warn("Failed to iterate kernel bad-flags map for stale cleanup")
	}
	removed := 0
	for _, k := range keysToDelete {
		if err := m.Delete(&k); err == nil {
			removed++
		} else if logger != nil {
			logger.WithError(err).WithField("map", mapName).Debug("Failed to delete stale kernel bad-flags entry")
		}
	}
	return removed
}

func pruneKernelBadFlagsMapV6(m *cebpf.Map, cutoffNS uint64, logger *logrus.Logger, mapName string) int {
	if m == nil || cutoffNS == 0 {
		return 0
	}
	var key [16]byte
	var val ebpf.BadFlagsInfo
	iter := m.Iterate()
	keysToDelete := make([][16]byte, 0)
	for iter.Next(&key, &val) {
		if val.LastSeen != 0 && val.LastSeen < cutoffNS {
			keysToDelete = append(keysToDelete, key)
		}
	}
	if err := iter.Err(); err != nil && logger != nil {
		logger.WithError(err).WithField("map", mapName).Warn("Failed to iterate kernel bad-flags v6 map for stale cleanup")
	}
	removed := 0
	for _, k := range keysToDelete {
		if err := m.Delete(&k); err == nil {
			removed++
		} else if logger != nil {
			logger.WithError(err).WithField("map", mapName).Debug("Failed to delete stale kernel bad-flags v6 entry")
		}
	}
	return removed
}

func pruneKernelPendingHandshakesMap(m *cebpf.Map, cutoffNS uint64, logger *logrus.Logger, mapName string) int {
	if m == nil || cutoffNS == 0 {
		return 0
	}
	var key ebpf.TcpSessionKey
	var val ebpf.HandshakeStatusGeneric
	iter := m.Iterate()
	keysToDelete := make([]ebpf.TcpSessionKey, 0)
	for iter.Next(&key, &val) {
		if val.BeginTime != 0 && val.BeginTime < cutoffNS {
			keysToDelete = append(keysToDelete, key)
		}
	}
	if err := iter.Err(); err != nil && logger != nil {
		logger.WithError(err).WithField("map", mapName).Warn("Failed to iterate kernel pending-handshakes map for stale cleanup")
	}
	removed := 0
	for _, k := range keysToDelete {
		if err := m.Delete(&k); err == nil {
			removed++
		} else if logger != nil {
			logger.WithError(err).WithField("map", mapName).Debug("Failed to delete stale kernel pending-handshake entry")
		}
	}
	return removed
}

func pruneKernelPendingHandshakesMapV6(m *cebpf.Map, cutoffNS uint64, logger *logrus.Logger, mapName string) int {
	if m == nil || cutoffNS == 0 {
		return 0
	}
	var key ebpf.TcpSessionKeyV6
	var val ebpf.HandshakeStatusGeneric
	iter := m.Iterate()
	keysToDelete := make([]ebpf.TcpSessionKeyV6, 0)
	for iter.Next(&key, &val) {
		if val.BeginTime != 0 && val.BeginTime < cutoffNS {
			keysToDelete = append(keysToDelete, key)
		}
	}
	if err := iter.Err(); err != nil && logger != nil {
		logger.WithError(err).WithField("map", mapName).Warn("Failed to iterate kernel pending-handshakes v6 map for stale cleanup")
	}
	removed := 0
	for _, k := range keysToDelete {
		if err := m.Delete(&k); err == nil {
			removed++
		} else if logger != nil {
			logger.WithError(err).WithField("map", mapName).Debug("Failed to delete stale kernel pending-handshake v6 entry")
		}
	}
	return removed
}

func pruneKernelIncompleteHandshakeCountMap(m *cebpf.Map, cutoffNS uint64, logger *logrus.Logger, mapName string) int {
	if m == nil {
		return 0
	}
	var key uint32
	var val ebpf.IncompleteHandshakeCount
	iter := m.Iterate()
	keysToDelete := make([]uint32, 0)
	for iter.Next(&key, &val) {
		if val.Count == 0 || (cutoffNS != 0 && val.LastUpdated != 0 && val.LastUpdated < cutoffNS) {
			keysToDelete = append(keysToDelete, key)
		}
	}
	if err := iter.Err(); err != nil && logger != nil {
		logger.WithError(err).WithField("map", mapName).Warn("Failed to iterate incomplete-handshake count map for stale cleanup")
	}
	removed := 0
	for _, k := range keysToDelete {
		if err := m.Delete(&k); err == nil {
			removed++
		} else if logger != nil {
			logger.WithError(err).WithField("map", mapName).Debug("Failed to delete stale incomplete-handshake count entry")
		}
	}
	return removed
}

func pruneKernelIncompleteHandshakeCountMapV6(m *cebpf.Map, cutoffNS uint64, logger *logrus.Logger, mapName string) int {
	if m == nil {
		return 0
	}
	var key [16]byte
	var val ebpf.IncompleteHandshakeCount
	iter := m.Iterate()
	keysToDelete := make([][16]byte, 0)
	for iter.Next(&key, &val) {
		if val.Count == 0 || (cutoffNS != 0 && val.LastUpdated != 0 && val.LastUpdated < cutoffNS) {
			keysToDelete = append(keysToDelete, key)
		}
	}
	if err := iter.Err(); err != nil && logger != nil {
		logger.WithError(err).WithField("map", mapName).Warn("Failed to iterate incomplete-handshake count v6 map for stale cleanup")
	}
	removed := 0
	for _, k := range keysToDelete {
		if err := m.Delete(&k); err == nil {
			removed++
		} else if logger != nil {
			logger.WithError(err).WithField("map", mapName).Debug("Failed to delete stale incomplete-handshake count v6 entry")
		}
	}
	return removed
}

func (c *Collector) runBlockGC() {
	defer c.wg.Done()

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.gcExpiredBlocks()
		}
	}
}

func (c *Collector) gcExpiredBlocks() {
	if c.Maps == nil || c.Maps.BlockedIPs == nil {
		return
	}

	v4List, v6List := c.Maps.ListBlockedIPs(c.Config.BlockDuration)

	for _, info := range v4List {
		if info.RemainingTTL == "expired" {
			ip := net.ParseIP(info.IP)
			if ip != nil {
				c.Maps.UnblockIP(ip)
				c.Logger.WithField("ip", info.IP).Debug("GC: Unblocked expired IP")
			}
		}
	}
	for _, info := range v6List {
		if info.RemainingTTL == "expired" {
			ip := net.ParseIP(info.IP)
			if ip != nil {
				c.Maps.UnblockIP(ip)
				c.Logger.WithField("ip", info.IP).Debug("GC: Unblocked expired IPv6")
			}
		}
	}
}

func (c *Collector) startCollectorMetricsServer() *http.Server {
	registry := prometheus.NewRegistry()

	registry.MustRegister(metrics.KernelIncidents)
	registry.MustRegister(metrics.KernelDroppedPacketsExact)
	registry.MustRegister(metrics.KernelStateCleanupDurationMilliseconds)
	registry.MustRegister(metrics.PerfLostSamples)
	registry.MustRegister(metrics.IncompleteHandshakeBlocks)

	for reason := uint32(1); reason < uint32(ebpf.IncidentMax); reason++ {
		name := ebpf.IncidentReasonName(uint8(reason))
		metrics.KernelIncidents.WithLabelValues(name).Add(0)
		metrics.KernelDroppedPacketsExact.WithLabelValues(name).Add(0)
	}

	metrics.PerfLostSamples.WithLabelValues("incidents").Add(0)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	return &http.Server{
		Addr:              c.Config.MetricsAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
}

func joinErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	msg := make([]string, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			msg = append(msg, err.Error())
		}
	}
	if len(msg) == 0 {
		return nil
	}
	return errors.New(strings.Join(msg, "; "))
}
