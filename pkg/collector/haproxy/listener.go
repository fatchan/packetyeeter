package haproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"PacketYeeter/pkg/metrics"

	"github.com/dropmorepackets/haproxy-go/peers"
	"github.com/dropmorepackets/haproxy-go/peers/sticktable"
)

const (
	blockFeedTableName  = "packetyeeter_block_feed"
	http3SeenTableName  = "packetyeeter_http3_seen"
	defaultHTTP3SeenTTL = 10 * time.Minute
)

// Blocker is the subset of *ebpf.Maps this package depends on. It exists so
// the peer listener can be exercised in tests (including real-haproxy e2e
// tests) without a loaded eBPF program/kernel maps.
type Blocker interface {
	BlockIP(ip net.IP, reason string, meta logrus.Fields) error
	MarkHTTP3SeenIP(ip net.IP, ttl time.Duration) error
}

type Server struct {
	port                   int
	blocker                Blocker
	http3SeenTTL           time.Duration
	verboseMapEntryUpdates bool

	mu       sync.Mutex
	listener net.Listener
	stopOnce sync.Once
}

func NewServer(port int, blocker Blocker, http3SeenTTL time.Duration, verboseMapEntryUpdates bool) *Server {
	if http3SeenTTL <= 0 {
		http3SeenTTL = defaultHTTP3SeenTTL
	}
	return &Server{
		port:                   port,
		blocker:                blocker,
		http3SeenTTL:           http3SeenTTL,
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
				http3SeenTTL:           s.http3SeenTTL,
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
	http3SeenTTL           time.Duration
	verboseMapEntryUpdates bool
}

func (h *handler) HandleHandshake(ctx context.Context, handshake *peers.Handshake) {
	// logrus.WithField("peer", handshake.LocalPeerIdentifier).Debug("HAProxy Handshake")
}

func (h *handler) HandleUpdate(ctx context.Context, update *sticktable.EntryUpdate) {
	if update == nil {
		return
	}

	tableName := ""
	if update.StickTable != nil {
		tableName = update.StickTable.Name
	}

	if h.verboseMapEntryUpdates {
		fmt.Printf("HAProxy peer update received: table=%q key=%q update=%s\n", tableName, update.Key.String(), update.String())
	}

	ipStr := update.Key.String()
	ip := net.ParseIP(ipStr)
	if ip == nil {
		logrus.WithFields(logrus.Fields{
			"table": tableName,
			"key":   ipStr,
		}).Warn("Ignoring HAProxy peer update with non-IP key")
		return
	}

	switch tableName {
	case blockFeedTableName:
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
	default:
		if h.verboseMapEntryUpdates {
			logrus.WithFields(logrus.Fields{
				"ip":          ip.String(),
				"stick_table": tableName,
			}).Debug("Ignoring HAProxy peer update for unrecognized stick-table")
		}
	}
}

func (h *handler) HandleError(ctx context.Context, err error) {
	logrus.WithError(err).Error("HAProxy Peer Protocol Error")
}

func (h *handler) Close() error {
	return nil
}
