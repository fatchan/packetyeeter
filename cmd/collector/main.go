package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"PacketYeeter/pkg/buildinfo"
	"PacketYeeter/pkg/collector"
	"PacketYeeter/pkg/collector/ebpf"
)

func main() {
	var (
		iface                        = flag.String("i", "eth0", "Network interface(s) to attach to; accepts a single interface or a comma-separated list like eth0,eth1")
		interfaces                   = flag.String("interfaces", "", "Explicit comma-separated list of network interfaces to attach to, e.g. eth0,eth1,eth2")
		metricsAddr                  = flag.String("metrics-addr", ":2112", "Prometheus metrics HTTP listen address")
		haproxyPort                  = flag.Int("haproxy-port", 0, "HAProxy peer protocol port")
		socketPath                   = flag.String("socket", "/var/run/packetyeeter-collector.sock", "Unix socket for CLI")
		geoIPASNPath                 = flag.String("geoip-asn", "", "Path to GeoLite2-ASN.mmdb")
		dynamicAllowlistSocketPath   = flag.String("dynamic-allowlist-socket-path", "", "Path to HAProxy runtime Unix socket for dynamic allowlist syncing; if empty, dynamic allowlist syncing is disabled")
		dynamicAllowlistInterval     = flag.Duration("dynamic-allowlist-interval", 60*time.Second, "How often to refresh the dynamic allowlist")
		haproxyWhitelistMapPath      = flag.String("haproxy-whitelist-map-path", "/etc/haproxy/maps/whitelist.map", "Path to the HAProxy whitelist map containing incoming IPs to always allow")
		haproxyBackendsMapPath       = flag.String("haproxy-backends-map-path", "/etc/haproxy/map/hosts.map", "Path to the HAProxy backends map containing backend hosts to always allow")
		blockDuration                = flag.Duration("block-duration", 5*time.Minute, "Default block duration")
		pollInterval                 = flag.Duration("poll-interval", 1*time.Second, "How often to poll eBPF maps")
		icmpThreshold                = flag.Uint("icmp-threshold", 0, "Kernel/XDP ICMP per-source PPS threshold (0 = use built-in BPF default)")
		udpThreshold                 = flag.Uint("udp-threshold", 0, "Kernel/XDP UDP per-source PPS threshold (0 = use built-in BPF default)")
		incompleteHandshakeThreshold = flag.Uint("incomplete-handshake-threshold", 0, "Collector-side recent incomplete-handshake count required to auto-block a source IP (0 = disabled)")
		http3SeenTTL                 = flag.Duration("http3-seen-ttl", 10*time.Minute, "How long a peer-fed HTTP/3-seen IP should be exempt from UDP rate limiting")
		verboseMapEntryUpdates       = flag.Bool("verbose-map-entry-updates", true, "Enable verbose logging for HAProxy peer stick-table/map entry updates")
		dryRun                       = flag.Bool("dry-run", false, "Monitor mode: log/count the collector's own kernel-space detections (bad flags, SYN flood, ICMP/UDP rate limits) without dropping traffic")
		udpFragMode                  = flag.String("udp-frag-mode", "drop", "Fragmented UDP / IPv6 fragment policy: rate (default, rate-limit only) or drop (legacy hard-drop)")
		showVersion                  = flag.Bool("version", false, "Print build version and exit")
		verbose                      = flag.Bool("v", false, "Verbose logging")
	)
	flag.Parse()
	if *showVersion {
		fmt.Println(buildinfo.String())
		return
	}

	logger := logrus.New()
	if *verbose {
		logger.SetLevel(logrus.DebugLevel)
	}
	logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

	fragMode, err := ebpf.ParseUDPFragMode(*udpFragMode)
	if err != nil {
		logrus.WithError(err).Fatal("Invalid -udp-frag-mode")
	}

	cfg := collector.Config{
		Interface:                    *iface,
		Interfaces:                   []string{*interfaces},
		MetricsAddr:                  *metricsAddr,
		HAProxyPort:                  *haproxyPort,
		SocketPath:                   *socketPath,
		GeoIPASNPath:                 *geoIPASNPath,
		DynamicAllowlistSocketPath:   *dynamicAllowlistSocketPath,
		DynamicAllowlistInterval:     *dynamicAllowlistInterval,
		HAProxyWhitelistMapPath:      *haproxyWhitelistMapPath,
		HAProxyBackendsMapPath:       *haproxyBackendsMapPath,
		BlockDuration:                *blockDuration,
		PollInterval:                 *pollInterval,
		ICMPThreshold:                uint32(*icmpThreshold),
		UDPThreshold:                 uint32(*udpThreshold),
		IncompleteHandshakeThreshold: uint32(*incompleteHandshakeThreshold),
		HTTP3SeenTTL:                 *http3SeenTTL,
		VerboseMapEntryUpdates:       *verboseMapEntryUpdates,
		DryRun:                       *dryRun,
		UDPFragMode:                  fragMode,
	}

	coll, err := collector.New(cfg, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create collector")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := coll.Start(ctx); err != nil {
		logger.WithError(err).Fatal("Failed to start collector")
	}

	logger.WithFields(logrus.Fields{
		"interfaces": coll.Config.Interfaces,
	}).Info("PacketYeeter Collector started")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down collector...")
	cancel()

	done := make(chan struct{})
	go func() {
		coll.Stop()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("Collector stopped gracefully")
	case <-time.After(5 * time.Second):
		logger.Warn("Shutdown timeout - forcing exit")
	}
}
