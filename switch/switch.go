package ethswitch

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/lab47/lnf/pkg/lldp"
	"github.com/lab47/lsvd/logger"
	"github.com/mdlayher/ethernet"
)

type PortDevice interface {
	Receive(ctx context.Context, fn func(frame []byte) error)
	Transmit(ctx context.Context, frame []byte) error
}

type Port struct {
	Name      string
	Device    PortDevice
	CreatedAt time.Time
	LastFrame time.Time

	TxCount uint64
	RxCount uint64

	tick *time.Ticker
}

type Switch struct {
	log logger.Logger

	mu    sync.Mutex
	ports map[string]*Port
	tbl   map[string]*Port
}

func NewSwitch(log logger.Logger) *Switch {
	s := &Switch{
		log:   log,
		ports: make(map[string]*Port),
		tbl:   make(map[string]*Port),
	}

	return s
}

func (s *Switch) AddPort(ctx context.Context, name string, dev PortDevice) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	port := &Port{
		Name:      name,
		Device:    dev,
		CreatedAt: time.Now(),
		tick:      time.NewTicker(1 * time.Minute),
	}
	s.ports[name] = port

	go s.portTick(ctx, port)

	go dev.Receive(ctx, func(frame []byte) error {
		return s.inputFrame(ctx, port, frame)
	})

	return nil
}

func (s *Switch) portTick(ctx context.Context, port *Port) {
	for {
		select {
		case <-ctx.Done():
			return

		case <-port.tick.C:
			err := s.sendLLDP(ctx, port)
			if err != nil {
				s.log.Error("error sending lldp", "error", err, "port", port.Name)
			}
		}
	}
}

var (
	lldpDest net.HardwareAddr
	noSrc    net.HardwareAddr
)

func init() {
	lldpDest, _ = net.ParseMAC("01:80:c2:00:00:0e")
	noSrc, _ = net.ParseMAC("00:00:00:00:00:00")
}

func (s *Switch) sendLLDP(ctx context.Context, port *Port) error {
	lfr := lldp.Frame{
		ChassisID: &lldp.ChassisID{
			Subtype: lldp.ChassisIDSubtypeInterfaceName,
			ID:      []byte("sys0"),
		},
		PortID: &lldp.PortID{
			Subtype: lldp.PortIDSubtypeInterfaceName,
			ID:      []byte(port.Name),
		},
		TTL: 1 * time.Minute,
	}

	lld, err := lfr.MarshalBinary()
	if err != nil {
		return err
	}

	fr := ethernet.Frame{
		Destination: lldpDest,
		Source:      noSrc,
		EtherType:   lldp.EtherType,
		Payload:     lld,
	}

	pktData, err := fr.MarshalBinary()
	if err != nil {
		return err
	}

	return port.Device.Transmit(ctx, pktData)
}

func (s *Switch) learn(port *Port, src string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tbl[src] = port
}

func (s *Switch) lookup(dest string) *Port {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.tbl[dest]
}

func (s *Switch) inputFrame(ctx context.Context, port *Port, frame []byte) error {
	port.LastFrame = time.Now()
	port.RxCount++

	dest := net.HardwareAddr(frame[0:6])

	src := net.HardwareAddr(frame[6:12])

	s.learn(port, src.String())

	destPort := s.lookup(dest.String())
	if destPort == nil {
		return s.broadcast(ctx, port, frame)
	} else {
		return s.txTo(ctx, destPort, frame)
	}
}

func (s *Switch) broadcast(ctx context.Context, srcPort *Port, frame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, port := range s.ports {
		if port == srcPort {
			continue
		}

		s.txTo(ctx, port, frame)
	}

	return nil
}

func (s *Switch) txTo(ctx context.Context, destPort *Port, frame []byte) error {
	return destPort.Device.Transmit(ctx, frame)
}
