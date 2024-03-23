package ethswitch

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/lab47/lnf/pkg/lldp"
	"github.com/lab47/lsvd/logger"
	"github.com/mdlayher/ethernet"
)

type PortDevice interface {
	ReceiveFrame(ctx context.Context, fn func(frame []byte) error) error
	TransmitFrame(ctx context.Context, frame *Frame) error
}

type PortMetadata struct {
	PortId              string
	SystemName          string
	ManagementAddresses []netip.Addr
	Description         string
}

type Port struct {
	Name      string
	Device    PortDevice
	CreatedAt time.Time
	LastFrame time.Time

	TxCount uint64
	RxCount uint64

	Metadata *PortMetadata

	tick   *time.Ticker
	cancel func()
}

type Switch struct {
	log logger.Logger

	mu    sync.Mutex
	ports map[string]*Port
	tbl   map[HardwareAddr]*Port

	nextPortNum int64
}

func NewSwitch(log logger.Logger) *Switch {
	s := &Switch{
		log:   log,
		ports: make(map[string]*Port),
		tbl:   make(map[HardwareAddr]*Port),

		nextPortNum: 100,
	}

	s.AddInternalPort()

	return s
}

func (s *Switch) NextPortName() string {
	id := s.nextPortNum
	s.nextPortNum++

	return fmt.Sprintf("p%d", id)
}

func (s *Switch) AddInternalPort() {
	s.mu.Lock()
	defer s.mu.Unlock()

	ip := &InternalPort{
		sw: s,
	}

	port := &Port{
		Name:      "p0",
		Device:    ip,
		CreatedAt: time.Now(),
		tick:      time.NewTicker(1 * time.Minute),
		cancel:    func() {},
	}

	s.log.Trace("added internal port", "name", port.Name)

	s.ports[port.Name] = port
}

func (s *Switch) AddPort(ctx context.Context, name string, dev PortDevice) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, cancel := context.WithCancel(ctx)

	port := &Port{
		Name:      name,
		Device:    dev,
		CreatedAt: time.Now(),
		tick:      time.NewTicker(1 * time.Minute),
		cancel:    cancel,
	}
	s.ports[name] = port

	go s.portTick(ctx, port)

	go dev.ReceiveFrame(ctx, func(frame []byte) error {
		return s.inputFrame(ctx, port, frame)
	})

	return nil
}

func (s *Switch) DelPort(ctx context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	port := s.ports[name]

	if port == nil {
		return nil
	}

	port.cancel()

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

	return port.Device.TransmitFrame(ctx, NewFrame(pktData, nil))
}

func (s *Switch) learn(port *Port, src HardwareAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if curPort, ok := s.tbl[src]; !ok || curPort != port {
		s.log.Trace("learned port", "port", port.Name, "src-addr", src)
		s.tbl[src] = port
	}
}

func (s *Switch) lookup(dest HardwareAddr) *Port {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.tbl[dest]
}

func (s *Switch) inputFrame(ctx context.Context, port *Port, data []byte) error {
	port.LastFrame = time.Now()
	port.RxCount++

	dest := HardwareAddr(data[0:6])

	src := HardwareAddr(data[6:12])

	s.learn(port, src)

	frame := NewFrame(data, port)
	defer frame.Discard(s.log)

	destPort := s.lookup(dest)
	if destPort == nil {
		s.log.Trace("broadcasting frame")
		return s.broadcast(ctx, port, frame)
	} else {
		s.log.Trace("unicasting frame")
		return s.txTo(ctx, destPort, frame)
	}
}

func (s *Switch) broadcast(ctx context.Context, srcPort *Port, frame *Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, port := range s.ports {
		if port == srcPort {
			continue
		}

		err := s.txTo(ctx, port, frame)
		if err != nil {
			s.log.Error("error transmitting to port", "port", port.Name, "error", err)
		}
	}

	return nil
}

func (s *Switch) txTo(ctx context.Context, destPort *Port, frame *Frame) error {
	return destPort.Device.TransmitFrame(ctx, frame)
}
