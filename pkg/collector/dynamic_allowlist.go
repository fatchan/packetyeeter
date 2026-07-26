package collector

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// FetchDynamicAllowlist returns the desired runtime allowlist entries.
//
// Replace this implementation with whatever external source you want to use.
// Entries may be plain IPs or CIDRs. Plain IPs are normalized to /32 or /128.
func FetchDynamicAllowlist(host string) ([]string, error) {
	_ = host
	return []string{}, nil
}

func (c *Collector) syncDynamicAllowlist() {
	entries, err := FetchDynamicAllowlist(c.Config.DynamicAllowlistHost)
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
		"host":    c.Config.DynamicAllowlistHost,
		"desired": len(desiredByKey),
		"added":   added,
		"removed": removed,
		"invalid": invalidCount,
	}).Debug("Dynamic allowlist sync complete")
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
