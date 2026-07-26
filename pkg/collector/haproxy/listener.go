package haproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/sirupsen/logrus"

	"PacketYeeter/pkg/metrics"

	"github.com/dropmorepackets/haproxy-go/peers"
	"github.com/dropmorepackets/haproxy-go/peers/sticktable"
)

// Blocker is the subset of *ebpf.Maps this package depends on. It exists so
// the peer listener can be exercised in tests (including real-haproxy e2e
// tests) without a loaded eBPF program/kernel maps.
type Blocker interface {
	BlockIP(ip net.IP, reason string, meta logrus.Fields) error
}

type Server struct {
	port    int
	blocker Blocker

	mu       sync.Mutex
	listener net.Listener
	stopOnce sync.Once
}

func NewServer(port int, blocker Blocker) *Server {
	return &Server{
		port:    port,
		blocker: blocker,
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
			return &handler{blocker: s.blocker}
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
	blocker Blocker
}

func (h *handler) HandleHandshake(ctx context.Context, handshake *peers.Handshake) {
	// logrus.WithField("peer", handshake.LocalPeerIdentifier).Debug("HAProxy Handshake")
}

func (h *handler) HandleUpdate(ctx context.Context, update *sticktable.EntryUpdate) {
	ipStr := update.Key.String()
	ip := net.ParseIP(ipStr)
	if ip != nil {
		h.blocker.BlockIP(ip, "HAProxy Peer Update", logrus.Fields{
			"source": "haproxy",
		})
		metrics.HAProxyBlocks.Inc()
	}
}

func (h *handler) HandleError(ctx context.Context, err error) {
	logrus.WithError(err).Error("HAProxy Peer Protocol Error")
}

func (h *handler) Close() error {
	return nil
}
