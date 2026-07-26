package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	runtimeapi "github.com/haproxytech/client-native/v6/runtime"
	runtimeopts "github.com/haproxytech/client-native/v6/runtime/options"
	"github.com/sirupsen/logrus"
)

type haproxyBackendTarget struct {
	H string `json:"h"`
}

// FetchDynamicAllowlist returns the desired runtime allowlist entries.
//
// It reads the HAProxy runtime whitelist map and backend map, returning:
//   - whitelist map keys directly
//   - backend target host IPs extracted from JSON value[].h (host:port)
func FetchDynamicAllowlist(socketPath, whitelistMapPath, backendsMapPath string) ([]string, error) {
	sockets := runtimeopts.Sockets(map[int]string{1: socketPath})
	rt, err := runtimeapi.New(context.Background(), sockets, runtimeopts.MapsDir("/etc/haproxy/map"))
	if err != nil {
		return nil, fmt.Errorf("create HAProxy runtime client: %w", err)
	}

	var out []string

	if whitelistMapPath != "" {
		entries, err := rt.ShowMapEntries(whitelistMapPath)
		if err != nil {
			return nil, fmt.Errorf("read whitelist map %q: %w", whitelistMapPath, err)
		}
		for _, entry := range entries {
			if entry == nil {
				continue
			}
			key := strings.TrimSpace(entry.Key)
			if key == "" {
				continue
			}
			out = append(out, key)
		}
	}

	if backendsMapPath != "" {
		entries, err := rt.ShowMapEntries(backendsMapPath)
		if err != nil {
			return nil, fmt.Errorf("read backends map %q: %w", backendsMapPath, err)
		}
		for _, entry := range entries {
			if entry == nil {
				continue
			}
			value := strings.TrimSpace(entry.Value)
			if value == "" {
				continue
			}

			var targets []haproxyBackendTarget
			if err := json.Unmarshal([]byte(value), &targets); err != nil {
				continue
			}

			for _, target := range targets {
				h := strings.TrimSpace(target.H)
				if h == "" {
					continue
				}

				hostPart, _, err := net.SplitHostPort(h)
				if err != nil {
					if idx := strings.LastIndex(h, ":"); idx > 0 {
						hostPart = h[:idx]
					} else {
						hostPart = h
					}
				}

				hostPart = strings.TrimSpace(strings.Trim(hostPart, "[]"))
				if hostPart == "" {
					continue
				}

				out = append(out, hostPart)
			}
		}
	}

	return out, nil
}

func (c *Collector) syncDynamicAllowlist() {
	entries, err := FetchDynamicAllowlist(c.Config.DynamicAllowlistSocketPath, c.Config.HAProxyWhitelistMapPath, c.Config.HAProxyBackendsMapPath)
	if err != nil {
		c.Logger.WithError(err).Warn("Failed to fetch dynamic allowlist")
		return
	}

	desired, invalidCount := parseDynamicAllowlistEntries(entries, c.Logger)
	current := c.snapshotDynamicAllowlist()

	currentByKey := make(map[string]*net.IPNet, len(current))
	for _, n := range current {
		currentByKey[normalizeIPNet(n)] = n
	}

	desiredByKey := make(map[string]*net.IPNet, len(desired))
	for _, n := range desired {
		desiredByKey[normalizeIPNet(n)] = n
	}

	added := 0
	removed := 0

	for key, n := range desiredByKey {
		if _, exists := currentByKey[key]; exists {
			continue
		}
		c.addDynamicAllowlistEntry(n)
		added++
	}

	for key, n := range currentByKey {
		if _, exists := desiredByKey[key]; exists {
			continue
		}
		c.removeDynamicAllowlistEntry(n)
		removed++
	}

	c.Logger.WithFields(logrus.Fields{
		"socket_path":                 c.Config.DynamicAllowlistSocketPath,
		"whitelist_map_path":          c.Config.HAProxyWhitelistMapPath,
		"backends_map_path":           c.Config.HAProxyBackendsMapPath,
		"fetched_entries":             len(entries),
		"desired_allowlist_entries":   len(desiredByKey),
		"current_dynamic_allowlisted": len(c.snapshotDynamicAllowlist()),
		"added":                       added,
		"removed":                     removed,
		"invalid":                     invalidCount,
	}).Info("Dynamic allowlist sync complete")
}

func (c *Collector) runDynamicAllowlistSync() {
	defer c.wg.Done()

	interval := c.Config.DynamicAllowlistInterval
	if interval <= 0 {
		interval = 60 * time.Second
	}

	c.syncDynamicAllowlist()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.syncDynamicAllowlist()
		}
	}
}

func parseDynamicAllowlistEntries(entries []string, logger *logrus.Logger) ([]*net.IPNet, int) {
	var nets []*net.IPNet
	invalidCount := 0

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		normalized := entry
		if !strings.Contains(normalized, "/") {
			if strings.Contains(normalized, ":") {
				normalized += "/128"
			} else {
				normalized += "/32"
			}
		}

		_, ipNet, err := net.ParseCIDR(normalized)
		if err != nil {
			invalidCount++
			logger.WithError(err).WithField("entry", entry).Warn("Invalid dynamic allowlist entry")
			continue
		}
		nets = append(nets, ipNet)
	}

	sort.Slice(nets, func(i, j int) bool {
		return normalizeIPNet(nets[i]) < normalizeIPNet(nets[j])
	})

	return dedupeIPNets(nets), invalidCount
}

func dedupeIPNets(nets []*net.IPNet) []*net.IPNet {
	if len(nets) == 0 {
		return nil
	}

	result := make([]*net.IPNet, 0, len(nets))
	seen := make(map[string]struct{}, len(nets))
	for _, n := range nets {
		key := normalizeIPNet(n)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, n)
	}
	return result
}

func normalizeIPNet(n *net.IPNet) string {
	if n == nil {
		return ""
	}
	return n.String()
}

func sortAllowlistEntries(entries []allowlistEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Dynamic == entries[j].Dynamic {
			return entries[i].CIDR < entries[j].CIDR
		}
		return !entries[i].Dynamic && entries[j].Dynamic
	})
}

func (c *Collector) snapshotDynamicAllowlist() []*net.IPNet {
	c.allowlistMu.RLock()
	defer c.allowlistMu.RUnlock()

	result := make([]*net.IPNet, 0, len(c.dynamicAllowedNets))
	for _, n := range c.dynamicAllowedNets {
		result = append(result, n)
	}
	return result
}

func (c *Collector) addDynamicAllowlistEntry(ipNet *net.IPNet) {
	key := normalizeIPNet(ipNet)

	c.allowlistMu.Lock()
	if _, exists := c.dynamicAllowedNets[key]; exists {
		c.allowlistMu.Unlock()
		return
	}
	c.dynamicAllowedNets[key] = ipNet
	c.allowedNets = append(c.allowedNets, ipNet)
	c.allowlistMu.Unlock()

	if err := c.Maps.AddAllowlistEntry(ipNet); err != nil {
		c.Logger.WithError(err).WithField("cidr", key).Warn("Failed to add dynamic allowlist entry to kernel-space map")
		return
	}

	c.Logger.WithField("cidr", key).Info("Added dynamic allowlist entry")
}

func (c *Collector) removeDynamicAllowlistEntry(ipNet *net.IPNet) {
	key := normalizeIPNet(ipNet)

	c.allowlistMu.Lock()
	if _, exists := c.dynamicAllowedNets[key]; !exists {
		c.allowlistMu.Unlock()
		return
	}
	delete(c.dynamicAllowedNets, key)

	filtered := make([]*net.IPNet, 0, len(c.allowedNets))
	for _, n := range c.allowedNets {
		if normalizeIPNet(n) == key {
			continue
		}
		filtered = append(filtered, n)
	}
	c.allowedNets = filtered
	c.allowlistMu.Unlock()

	if err := c.Maps.RemoveAllowlistEntry(ipNet); err != nil {
		c.Logger.WithError(err).WithField("cidr", key).Warn("Failed to remove dynamic allowlist entry from kernel-space map")
		return
	}

	c.Logger.WithField("cidr", key).Info("Removed dynamic allowlist entry")
}

func (c *Collector) dynamicAllowlistStatus() string {
	c.allowlistMu.RLock()
	defer c.allowlistMu.RUnlock()
	return fmt.Sprintf("dynamic=%d total=%d", len(c.dynamicAllowedNets), len(c.allowedNets))
}
