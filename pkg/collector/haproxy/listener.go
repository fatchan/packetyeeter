package haproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"PacketYeeter/pkg/metrics"

	"github.com/dropmorepackets/haproxy-go/peers"
	"github.com/dropmorepackets/haproxy-go/peers/sticktable"
)

const (
	blockFeedTableName        = "packetyeeter_block_feed"
	http3SeenTableName        = "packetyeeter_http3_seen"
	targetedDomainsTableName  = "packetyeeter_targeted_domains"
	defaultHTTP3SeenTTL       = 10 * time.Minute
	defaultTargetedDomainsTTL = 10 * time.Minute
)

// Blocker is the subset of *ebpf.Maps this package depends on. It exists so
// the peer listener can be exercised in tests (including real-haproxy e2e
// tests) without a loaded eBPF program/kernel maps.
type Blocker interface {
	BlockIP(ip net.IP, reason string, meta logrus.Fields) error
	MarkHTTP3SeenIP(ip net.IP, ttl time.Duration) error
}

type TargetedDomainTracker interface {
	MarkTargetedDomain(entry string, ttl time.Duration)
}

type Server struct {
	port                   int
	blocker                Blocker
	targetedDomainTracker  TargetedDomainTracker
	http3SeenTTL           time.Duration
	targetedDomainsTTL     time.Duration
	verboseMapEntryUpdates bool

	mu       sync.Mutex
	listener net.Listener
	stopOnce sync.Once
}

func NewServer(port int, blocker Blocker, targetedDomainTracker TargetedDomainTracker, http3SeenTTL time.Duration, targetedDomainsTTL time.Duration, verboseMapEntryUpdates bool) *Server {
	if http3SeenTTL <= 0 {
		http3SeenTTL = defaultHTTP3SeenTTL
	}
	if targetedDomainsTTL <= 0 {
		targetedDomainsTTL = defaultTargetedDomainsTTL
	}
	return &Server{
		port:                   port,
		blocker:                blocker,
		targetedDomainTracker:  targetedDomainTracker,
		http3SeenTTL:           http3SeenTTL,
		targetedDomainsTTL:     targetedDomainsTTL,
		verboseMapEntryUpdates: verboseMapEntryUpdates,
	}
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("127.0.0.1:%d", s.port)

	s.mu.Lock()
	if s.listener != nil {
		s.mu.Unlock()
		return fmt.Errorf("HAProxy peer listener already started")
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to listen for HAProxy peer protocol on %s: %w", addr, err)
	}
	s.listener = ln
	s.mu.Unlock()

	logrus.WithField("address", addr).Info("Starting HAProxy Peer Listener")

	peer := peers.Peer{
		Addr: addr,
		HandlerSource: func() peers.Handler {
			return &handler{
				blocker:                s.blocker,
				targetedDomainTracker:  s.targetedDomainTracker,
				http3SeenTTL:           s.http3SeenTTL,
				targetedDomainsTTL:     s.targetedDomainsTTL,
				verboseMapEntryUpdates: s.verboseMapEntryUpdates,
			}
		},
	}

	if err := peer.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("HAProxy peer listener serve failed: %w", err)
	}
	return nil
}

func (s *Server) Stop() error {
	var err error
	s.stopOnce.Do(func() {
		s.mu.Lock()
		ln := s.listener
		s.listener = nil
		s.mu.Unlock()
		if ln != nil {
			err = ln.Close()
		}
	})
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

type handler struct {
	blocker                Blocker
	targetedDomainTracker  TargetedDomainTracker
	http3SeenTTL           time.Duration
	targetedDomainsTTL     time.Duration
	verboseMapEntryUpdates bool
}

func (h *handler) HandleHandshake(ctx context.Context, handshake *peers.Handshake) {
	// No-op
}

func (h *handler) HandleUpdate(ctx context.Context, update *sticktable.EntryUpdate) {
	if update == nil {
		return
	}

	tableName := ""
	if update.StickTable != nil {
		tableName = update.StickTable.Name
	}

	keyStr := strings.TrimSpace(update.Key.String())
	if keyStr == "" {
		return
	}

	switch tableName {
	case blockFeedTableName:
		ip := net.ParseIP(keyStr)
		if ip == nil {
			logrus.WithFields(logrus.Fields{
				"table": tableName,
				"key":   keyStr,
			}).Warn("Ignoring HAProxy peer update with non-IP key")
			return
		}
		if err := h.blocker.BlockIP(ip, "HAProxy Peer Update", logrus.Fields{
			"source":      "haproxy",
			"stick_table": tableName,
		}); err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"ip":          ip.String(),
				"stick_table": tableName,
			}).Error("Failed to block IP from HAProxy peer update")
			return
		}
		metrics.HAProxyBlocks.Inc()
		logrus.WithFields(logrus.Fields{
			"ip":          ip.String(),
			"stick_table": tableName,
		}).Info("Blocked IP from HAProxy peer table update")
	case http3SeenTableName:
		ip := net.ParseIP(keyStr)
		if ip == nil {
			logrus.WithFields(logrus.Fields{
				"table": tableName,
				"key":   keyStr,
			}).Warn("Ignoring HAProxy peer update with non-IP key")
			return
		}
		if err := h.blocker.MarkHTTP3SeenIP(ip, h.http3SeenTTL); err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"ip":          ip.String(),
				"stick_table": tableName,
			}).Error("Failed to mark HTTP/3-seen IP from HAProxy peer update")
			return
		}
		if h.verboseMapEntryUpdates {
			logrus.WithFields(logrus.Fields{
				"ip":          ip.String(),
				"stick_table": tableName,
				"ttl":         h.http3SeenTTL,
			}).Info("Marked HTTP/3-seen IP from HAProxy peer table update")
		}
	case targetedDomainsTableName:
		if h.targetedDomainTracker == nil {
			return
		}
		h.targetedDomainTracker.MarkTargetedDomain(keyStr, h.targetedDomainsTTL)
		if h.verboseMapEntryUpdates {
			logrus.WithFields(logrus.Fields{
				"entry":       keyStr,
				"stick_table": tableName,
				"ttl":         h.targetedDomainsTTL,
			}).Info("Marked targeted domain from HAProxy peer table update")
		}
	default:
		if h.verboseMapEntryUpdates {
			logrus.WithFields(logrus.Fields{
				"key":         keyStr,
				"stick_table": tableName,
			}).Debug("Ignoring HAProxy peer update for unrecognized stick-table")
		}
	}
}

func (h *handler) Close() error {
	return nil
}
