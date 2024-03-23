package vhostuser

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	ringbuf "github.com/lab47/lnf/pkg/ring_buf"
	ethswitch "github.com/lab47/lnf/switch"
	"github.com/lab47/lsvd/logger"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// Implementation based on snabb's vhost bits.

const (
	VHOST_USER_MEMORY_MAX_NREGIONS = 8
	VHOST_MEMORY_MAX_NREGIONS      = 8
)

// vhost_user request types
const (
	VHOST_USER_NONE                  = 0
	VHOST_USER_GET_FEATURES          = 1
	VHOST_USER_SET_FEATURES          = 2
	VHOST_USER_SET_OWNER             = 3
	VHOST_USER_RESET_OWNER           = 4
	VHOST_USER_SET_MEM_TABLE         = 5
	VHOST_USER_SET_LOG_BASE          = 6
	VHOST_USER_SET_LOG_FD            = 7
	VHOST_USER_SET_VRING_NUM         = 8
	VHOST_USER_SET_VRING_ADDR        = 9
	VHOST_USER_SET_VRING_BASE        = 10
	VHOST_USER_GET_VRING_BASE        = 11
	VHOST_USER_SET_VRING_KICK        = 12
	VHOST_USER_SET_VRING_CALL        = 13
	VHOST_USER_SET_VRING_ERR         = 14
	VHOST_USER_GET_PROTOCOL_FEATURES = 15
	VHOST_USER_SET_PROTOCOL_FEATURES = 16
	VHOST_USER_GET_QUEUE_NUM         = 17
	VHOST_USER_SET_VRING_ENABLE      = 18
	VHOST_USER_MAX                   = 19
)

var requestNames = map[uint32]string{
	VHOST_USER_NONE:                  "none",
	VHOST_USER_GET_FEATURES:          "get_features",
	VHOST_USER_SET_FEATURES:          "set_features",
	VHOST_USER_SET_OWNER:             "set_owner",
	VHOST_USER_RESET_OWNER:           "reset_owner",
	VHOST_USER_SET_MEM_TABLE:         "set_mem_table",
	VHOST_USER_SET_LOG_BASE:          "set_log_base",
	VHOST_USER_SET_LOG_FD:            "set_log_fd",
	VHOST_USER_SET_VRING_NUM:         "set_vring_num",
	VHOST_USER_SET_VRING_ADDR:        "set_vring_addr",
	VHOST_USER_SET_VRING_BASE:        "set_vring_base",
	VHOST_USER_GET_VRING_BASE:        "get_vring_base",
	VHOST_USER_SET_VRING_KICK:        "set_vring_kick",
	VHOST_USER_SET_VRING_CALL:        "set_vring_call",
	VHOST_USER_SET_VRING_ERR:         "set_vring_err",
	VHOST_USER_GET_PROTOCOL_FEATURES: "get_protocol_features",
	VHOST_USER_SET_PROTOCOL_FEATURES: "set_protocol_features",
	VHOST_USER_GET_QUEUE_NUM:         "get_queue_num",
	VHOST_USER_SET_VRING_ENABLE:      "set_vring_enable",
	VHOST_USER_MAX:                   "max",
}

var kickBuf = make([]byte, 8)

func init() {
	binary.NativeEndian.PutUint64(kickBuf, 1)
}

type UserMemoryRegion struct {
	Guest_phys_addr uint64
	Memory_size     uint64
	Userspace_addr  uint64
	Mmap_offset     uint64
}

type UserMemory struct {
	Nregions uint32
	Padding  uint32
	Regions  []UserMemoryRegion
}

func (m *UserMsg) Memory() *UserMemory {
	um := &UserMemory{
		Nregions: binary.NativeEndian.Uint32(m.Body),
		Padding:  binary.NativeEndian.Uint32(m.Body[4:]),
	}

	r := m.Body[8:]
	for i := 0; i < int(um.Nregions); i++ {
		mr := UserMemoryRegion{
			Guest_phys_addr: binary.NativeEndian.Uint64(r),
			Memory_size:     binary.NativeEndian.Uint64(r[8:]),
			Userspace_addr:  binary.NativeEndian.Uint64(r[16:]),
			Mmap_offset:     binary.NativeEndian.Uint64(r[24:]),
		}

		um.Regions = append(um.Regions, mr)

		r = r[32:]
	}

	return um
}

const (
	VHOST_USER_VERSION_MASK    = (0x3)
	VHOST_USER_REPLY_MASK      = (0x1 << 2)
	VHOST_USER_VRING_IDX_MASK  = (0xff)
	VHOST_USER_VRING_NOFD_MASK = (0x1 << 8)
)

type UserMsgHeader struct {
	Request uint32
	Flags   uint32
	Size    uint32
}

type UserMsg struct {
	UserMsgHeader
	Body []byte
	Fds  []int
}

// vhost_memory structure is used to declare which memory address
// ranges we want to use for DMA. The kernel uses this to create a
// shared memory mapping.

/*
struct vhostu_memory_region {
  uint64_t guest_phys_addr;
  uint64_t memory_size;
  uint64_t userspace_addr;
  uint64_t flags_padding; // no flags currently specified
};
*/

/*
struct vhost_memory {
  uint32_t nregions;
  uint32_t padding;
  struct vhostu_memory_region regions[VHOST_MEMORY_MAX_NREGIONS];
};
*/

// vhost is the top-level structure that the application allocates and
// initializes to open a virtio/vhost network device.

type MemoryDesc [VHOST_VRING_SIZE]VRingDesc

type VRing struct {
	// eventfd(2) for notifying the kernel (kick) and being notified (call)
	kickFD, callFD int
	desc           [VHOST_VRING_SIZE]VRingDesc
	avail          VRingAvail
	used           VRingUsed
	//struct vring_desc desc[VHOST_VRING_SIZE] __attribute__((aligned(4)));
	//struct vring_avail avail                 __attribute__((aligned(2)));
	//struct vring_used used                   __attribute__((aligned(4096)));
	// XXX Hint: Adding this padding seems to reduce impact of heap corruption.
	// So perhaps it's writes to a vring structure that's over-running?
	// char pad[1000000];
}

type VHost struct {
	features uint64   // features negotiated with the kernel
	tapfd    int      // file descriptor for /dev/net/tun
	vhostfd  int      // file descriptor for /dev/vhost-net
	vring    [2]VRing // vring[0] is receive, vring[1] is transmit
}

// Below are structures imported from Linux headers.
// This is purely to avoid a compile-time dependency on those headers,
// which has been an problem on certain development machines.
type vhostu_vring_state struct {
	Index, Num uint32
}

func (m *UserMsg) VRingState() vhostu_vring_state {
	var v vhostu_vring_state

	v.Index = binary.NativeEndian.Uint32(m.Body)
	v.Num = binary.NativeEndian.Uint32(m.Body[4:])

	return v
}

type vhostu_vring_addr struct {
	Index, Flags                                                    uint32
	Desc_user_addr, Used_user_addr, Avail_user_addr, Log_guest_addr uint64
}

func (m *UserMsg) VRingAddr() (vhostu_vring_addr, error) {
	var v vhostu_vring_addr

	err := binary.Read(bytes.NewReader(m.Body), binary.NativeEndian, &v)

	return v, err
}

// These were printed out with a little throw-away C program.
const (
	VHOST_SET_VRING_NUM   = 0x4008af10
	VHOST_SET_VRING_BASE  = 0x4008af12
	VHOST_SET_VRING_KICK  = 0x4008af20
	VHOST_SET_VRING_CALL  = 0x4008af21
	VHOST_SET_VRING_ADDR  = 0x4028af11
	VHOST_SET_MEM_TABLE   = 0x4008af03
	VHOST_SET_OWNER       = 0x0000af01
	VHOST_GET_FEATURES    = 0x8008af00
	VHOST_NET_SET_BACKEND = 0x4008af30
)

const MaxVirtqPairs = 16

type Device struct {
	log  logger.Logger
	conn *net.UnixConn
	buf  []byte
	obuf []byte

	features  uint64
	mrg_rxbuf bool

	virtq       [MaxVirtqPairs * 2]*Virtq
	virtq_pairs uint32

	vhostReady bool

	closed atomic.Bool

	memTable []*MemoryTableEntry
	recv     *Virtq
	xmit     *Virtq

	xmitBuffers buffers

	pp PacketProcessor

	bufLock  atomic.Int32
	txBuf    *ringbuf.RingBuf[*ethswitch.Frame]
	txcharge chan struct{}
}

func NewDevice(log logger.Logger, conn *net.UnixConn, pp PacketProcessor) *Device {
	d := &Device{
		log:      log,
		conn:     conn,
		buf:      make([]byte, 1024*10),
		obuf:     make([]byte, 1024*10),
		pp:       pp,
		txBuf:    ringbuf.NewRingBuf[*ethswitch.Frame](1024),
		txcharge: make(chan struct{}, 1024),
	}

	d.initVirtq()

	return d
}

type Ring struct {
	desc  *DescArrayAccess
	avail *AvailAccess
	used  *UsedAccess
}

type Virtq struct {
	device   *Device
	indirect bool

	ring           *Ring
	last_avail_idx uint32
	last_used_idx  uint32

	num    uint32
	callFD int
	kickFD int

	callIO *os.File
	kickIO *os.File
}

func (d *Device) initVirtq() {
	d.virtq_pairs = 1
	for i := range d.virtq {
		d.virtq[i] = &Virtq{
			device: d,
		}
	}
}

func (d *Device) Receive(msg *UserMsg) error {
	n, oobn, flags, _, err := d.conn.ReadMsgUnix(d.buf[:12], d.obuf)
	if err != nil {
		return errors.Wrapf(err, "reading message header")
	}

	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return io.EOF
	}

	data := d.buf[:n]
	oob := d.obuf[:oobn]

	err = binary.Read(bytes.NewReader(data), binary.NativeEndian, &msg.UserMsgHeader)
	if err != nil {
		return err
	}

	msg.Fds = msg.Fds[:0]

	if oobn != 0 {
		cmsg, err := unix.ParseSocketControlMessage(oob)
		if err != nil {
			return err
		}

		fds, err := unix.ParseUnixRights(&cmsg[0])
		if err != nil {
			return err
		}

		msg.Fds = append(msg.Fds, fds...)
	}

	if msg.Size > 0 {
		body := d.buf[:msg.Size]

		_, err = io.ReadFull(d.conn, body)
		if err != nil {
			return err
		}

		msg.Body = append(msg.Body, body...)
	}

	return nil
}

func (d *Device) reply(msg *UserMsg, val uint64) error {
	msg.Flags = 5
	msg.Size = 8

	var buf bytes.Buffer
	err := binary.Write(&buf, binary.NativeEndian, msg.UserMsgHeader)
	if err != nil {
		return err
	}

	err = binary.Write(&buf, binary.NativeEndian, val)
	if err != nil {
		return err
	}

	n, err := d.conn.Write(buf.Bytes())

	d.log.Warn("replied", "buf", buf.Bytes(), "cnt", n)

	return err
}

func (d *Device) replyState(msg *UserMsg, s *vhostu_vring_state) error {
	msg.Flags = 5
	msg.Size = 8

	var buf bytes.Buffer
	err := binary.Write(&buf, binary.NativeEndian, msg.UserMsgHeader)
	if err != nil {
		return err
	}

	err = binary.Write(&buf, binary.NativeEndian, s)
	if err != nil {
		return err
	}

	_, err = d.conn.Write(buf.Bytes())
	return err
}

func (d *Device) Startup(ctx context.Context) error {
	var msg UserMsg

	for {
		if d.xmit != nil && d.recv != nil {
			go d.driveTx(ctx)
			return nil
		}

		msg.Body = msg.Body[:0]

		err := d.Receive(&msg)
		if err != nil {
			return err
		}

		err = d.dispatch(&msg)
		if err != nil {
			return err
		}
	}
}

func (d *Device) Close() error {
	d.closed.Store(true)

	if d.recv != nil {
		d.recv.kickIO.Close()
		d.recv.callIO.Close()
	}

	if d.xmit != nil {
		d.xmit.kickIO.Close()
		d.xmit.callIO.Close()
	}

	return nil
}

func (d *Device) Process() error {
	go d.watchTxCall()
	var msg UserMsg

	for {
		msg.Body = msg.Body[:0]

		err := d.Receive(&msg)
		if err != nil {
			return err
		}

		err = d.dispatch(&msg)
		if err != nil {
			return err
		}
	}
}

func (d *Device) dispatch(msg *UserMsg) error {
	d.log.Trace("vhost message", "request", requestNames[msg.Request], "flags", msg.Flags, "size", msg.Size)

	switch msg.Request {
	case VHOST_USER_NONE:
		return d.none(msg)
	case VHOST_USER_GET_FEATURES:
		return d.get_features(msg)
	case VHOST_USER_SET_FEATURES:
		return d.set_features(msg)
	case VHOST_USER_SET_OWNER:
		return d.set_owner(msg)
	case VHOST_USER_RESET_OWNER:
		return d.reset_owner(msg)
	case VHOST_USER_SET_MEM_TABLE:
		return d.set_mem_table(msg)
	case VHOST_USER_SET_LOG_BASE:
		return d.set_log_base(msg)
	case VHOST_USER_SET_LOG_FD:
		return d.set_log_fd(msg)
	case VHOST_USER_SET_VRING_NUM:
		return d.set_vring_num(msg)
	case VHOST_USER_SET_VRING_ADDR:
		return d.set_vring_addr(msg)
	case VHOST_USER_SET_VRING_BASE:
		return d.set_vring_base(msg)
	case VHOST_USER_GET_VRING_BASE:
		return d.get_vring_base(msg)
	case VHOST_USER_SET_VRING_KICK:
		return d.set_vring_kick(msg)
	case VHOST_USER_SET_VRING_CALL:
		return d.set_vring_call(msg)
	case VHOST_USER_SET_VRING_ERR:
		return d.set_vring_err(msg)
	case VHOST_USER_GET_PROTOCOL_FEATURES:
		return d.get_protocol_features(msg)
	case VHOST_USER_SET_PROTOCOL_FEATURES:
		return d.set_protocol_features(msg)
	case VHOST_USER_GET_QUEUE_NUM:
		return d.get_queue_num(msg)
	case VHOST_USER_SET_VRING_ENABLE:
		return d.set_vring_enable(msg)
	}
	return nil
}

const (
	VHOST_USER_F_PROTOCOL_FEATURES = 1 << 30
	VIRTIO_F_NOTIFY_ON_EMPTY       = 1 << 24 /* We notify when the ring is completely used,
	   even if the guest is suppressing callbacks */
	VIRTIO_F_ANY_LAYOUT         = 1 << 27 // Can the device handle any descriptor layout?
	VIRTIO_RING_F_INDIRECT_DESC = 1 << 28 // We support indirect buffer descriptors
	VIRTIO_RING_F_EVENT_IDX     = 1 << 29 /* The Guest publishes the used index for which
	   it expects an interrupt at the end of the avail
	   ring. Host should ignore the avail->flags field.
	   The Host publishes the avail index for which
	   it expects a kick at the end of the used ring.
	   Guest should ignore the used->flags field. */
	VIRTIO_F_BAD_FEATURE = 1 << 30 /* A guest should never accept this.  It implies
	   negotiation is broken. */
)

const supported_features = VIRTIO_F_ANY_LAYOUT +
	//VIRTIO_NET_F_CTRL_VQ +
	//VIRTIO_NET_F_MQ +
	//VIRTIO_NET_F_CSUM +
	VHOST_USER_F_PROTOCOL_FEATURES

func (d *Device) none(_ *UserMsg) error {
	// Empty in snabb
	d.log.Warn("got a none message from qemu")
	return nil
}

func (d *Device) get_features(msg *UserMsg) error {
	return d.reply(msg, supported_features)
}

func (m *UserMsg) u64() uint64 {
	return binary.NativeEndian.Uint64(m.Body)
}

func (d *Device) set_features(msg *UserMsg) error {
	f := msg.u64()
	d.log.Info("configuring features", "features", f)

	d.features = f

	if f&VIRTIO_NET_F_MRG_RXBUF != 0 {
		d.mrg_rxbuf = true
	} else {
		d.mrg_rxbuf = false
	}

	if f&VIRTIO_RING_F_INDIRECT_DESC != 0 {
		for _, q := range d.virtq {
			q.indirect = true
		}

	}

	return nil
}

func (d *Device) set_owner(_ *UserMsg) error {
	return nil
}

func (d *Device) reset_owner(_ *UserMsg) error {
	d.vhostReady = false
	return nil
}

type MemoryTableEntry struct {
	Data     []byte
	DataSize uint64
	Guest    uint64
	Qemu     uint64
	Offset   uint64
	MapSize  uint64

	MappedAddress uintptr
}

func (e *MemoryTableEntry) contains(addr uint64) bool {
	return addr >= e.Guest && addr < e.Guest+e.DataSize
}

func (e *MemoryTableEntry) containsQemu(addr uint64) bool {
	return addr >= e.Qemu && addr < e.Qemu+e.DataSize
}

func (d *Device) freeMemTable() {
	for _, ent := range d.memTable {
		unix.Munmap(ent.Data)
	}
}

func (d *Device) set_mem_table(msg *UserMsg) error {
	d.freeMemTable()
	d.memTable = nil

	mem := msg.Memory()

	for i, mr := range mem.Regions {
		fd := msg.Fds[i]
		d.log.Trace("configuring mem-table", "fd", fd,
			"guest", mr.Guest_phys_addr,
			"user/qemu", mr.Userspace_addr,
			"size", mr.Memory_size,
			"offset", mr.Mmap_offset,
		)

		size := mr.Memory_size // + mr.Mmap_offset

		ptr, err := unix.Mmap(fd, int64(mr.Mmap_offset), int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err != nil {
			return err
		}

		err = unix.Close(fd)
		if err != nil {
			d.log.Warn("error closing mmap fd", "error", err)
		}

		mappedAddress := uintptr(unsafe.Pointer(&ptr[0]))
		mappedAddress += uintptr(mr.Mmap_offset)

		// qemu_va + guest_phys + &ptr[0] + offset - guest_phys - user_addr

		d.memTable = append(d.memTable, &MemoryTableEntry{
			Data:          ptr,
			DataSize:      mr.Memory_size,
			Guest:         mr.Guest_phys_addr,
			Qemu:          mr.Userspace_addr,
			Offset:        mr.Mmap_offset,
			MapSize:       size,
			MappedAddress: mappedAddress - uintptr(mr.Guest_phys_addr),
		})
	}

	return nil
}

func (d *Device) fromQemuOffset(addr uint64) uint64 {
	for _, e := range d.memTable {
		if e.containsQemu(addr) {
			return addr - e.Qemu
		}
	}
	return 0
}

func (d *Device) mapFromQemu(addr uint64) []byte {
	for _, e := range d.memTable {
		if e.containsQemu(addr) {
			dpdk := addr + e.Guest + uint64(e.MappedAddress) - e.Qemu
			offset := addr - e.Qemu
			d.log.Trace("mapped address from qemu", "addr", addr,
				"region", e.Qemu, "region-size", e.DataSize, "offset", offset,
				"dpdk", dpdk, "dpdk-offset", dpdk-uint64(e.MappedAddress),
			)

			return e.Data[offset:]
		}
	}

	panic(fmt.Sprintf("mapping to host address failed: %d", addr))
}

func (d *Device) set_log_base(_ *UserMsg) error {
	// Not implemented in snabb
	return nil
}

func (d *Device) set_log_fd(_ *UserMsg) error {
	// Not implemented in snabb
	return nil
}

func (d *Device) set_vring_num(msg *UserMsg) error {
	s := msg.VRingState()

	d.virtq[s.Index].num = s.Num

	d.log.Info("virtq num set", "index", s.Index, "num", s.Num)

	pairs := (s.Index / 2) + 1
	if pairs > d.virtq_pairs {
		d.virtq_pairs = pairs
	}

	return nil
}

func (d *Device) decodeDesc(addr uint64) (*DescArrayAccess, error) {
	data := d.mapFromQemu(addr)

	return &DescArrayAccess{data[:VHOST_VRING_SIZE*32]}, nil
}

func (d *Device) decodeAvail(addr uint64) (*AvailAccess, error) {
	data := d.mapFromQemu(addr)

	return &AvailAccess{data[:4+(VHOST_VRING_SIZE*2)]}, nil
}

func (d *Device) decodeUsed(addr uint64) (*UsedAccess, error) {
	data := d.mapFromQemu(addr)

	return &UsedAccess{data[:4+(VHOST_VRING_SIZE*8)]}, nil
}

func (d *Device) set_vring_addr(msg *UserMsg) error {
	addr, err := msg.VRingAddr()
	if err != nil {
		return err
	}

	desc, err := d.decodeDesc(addr.Desc_user_addr)
	if err != nil {
		return err
	}

	used, err := d.decodeUsed(addr.Used_user_addr)
	if err != nil {
		return err
	}

	avail, err := d.decodeAvail(addr.Avail_user_addr)
	if err != nil {
		return err
	}

	d.virtq[addr.Index].ring = &Ring{
		desc:  desc,
		used:  used,
		avail: avail,
	}

	d.virtq[addr.Index].last_used_idx = uint32(used.Idx())

	d.log.Trace("vring address configured", "ring", addr.Index, "avail", used.Idx())

	//used.SetFlags(VRING_F_NO_NOTIFY)

	return nil
}

func (d *Device) set_vring_base(msg *UserMsg) error {
	state := msg.VRingState()

	d.virtq[state.Index].last_avail_idx = state.Num

	d.log.Trace("set vring avail", "avail", state.Num)

	return nil
}

func (d *Device) get_vring_base(msg *UserMsg) error {
	d.vhostReady = false
	state := msg.VRingState()

	state.Num = d.virtq[state.Index].last_avail_idx

	return d.replyState(msg, &state)
}

func (d *Device) set_vring_kick(msg *UserMsg) error {
	val := msg.u64()
	idx := val & VHOST_USER_VRING_IDX_MASK
	validFd := val&VHOST_USER_VRING_NOFD_MASK == 0

	d.vhostReady = true

	if validFd {
		d.virtq[idx].kickFD = msg.Fds[0]
		d.virtq[idx].kickIO = os.NewFile(uintptr(msg.Fds[0]), "call")
		d.log.Trace("configured kickfd", "ring", idx, "fd", msg.Fds[0])
	}

	return nil
}

func (d *Device) set_vring_call(msg *UserMsg) error {
	val := msg.u64()
	idx := val & VHOST_USER_VRING_IDX_MASK
	validFd := val&VHOST_USER_VRING_NOFD_MASK == 0

	if validFd {
		d.virtq[idx].callFD = msg.Fds[0]
		d.virtq[idx].callIO = os.NewFile(uintptr(msg.Fds[0]), "call")

		d.log.Trace("configured callfd", "ring", idx, "fd", msg.Fds[0])
	}

	return nil
}

func (d *Device) set_vring_err(_ *UserMsg) error {
	// Not implemented in snabb
	return nil
}

func (d *Device) set_protocol_features(_ *UserMsg) error {
	// Empty in snabb
	return nil
}

func (d *Device) get_protocol_features(msg *UserMsg) error {
	return d.reply(msg, 0)
}

func (d *Device) get_queue_num(_ *UserMsg) error {
	// Empty in snabb
	return nil
}

func (d *Device) watchTxCall() {
	v := d.xmit

	buf := make([]byte, 8)

	for {
		n, err := v.callIO.Read(buf)
		if err != nil {
			d.log.Error("error watching txcall", "error", err)
			return
		}

		if n != 0 {
			d.log.Trace("detected tx buffers ready")
		}
	}
}

func (d *Device) ReceiveFrame(ctx context.Context, fn func(frame []byte) error) error {
	v := d.recv

	kickBuf := make([]byte, 8)

	var output bytes.Buffer
	var b buffers

	f := v.kickIO

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if d.closed.Load() {
				return nil
			}
		}

		for {
			buffers, d_idx, err := d.getNextBuffer(v, &b)
			if err != nil {
				d.log.Error("error handling packets", "error", err)
				continue
			}

			if buffers == nil {
				break
			}

			output.Reset()

			for _, b := range buffers {
				output.Write(b)
			}

			d.log.Trace("gpv5: packet read", "size", output.Len())

			d.returnBuffer(v, buffers, d_idx)
			d.signalUsed(v)

			err = fn(output.Bytes()[virtio_net_hdr_size:])
			if err != nil {
				return err
			}
		}

		n, err := f.Read(kickBuf)
		if err != nil {
			d.log.Error("reading kick failed", "error", err)
			return err
		}

		d.log.Trace("kick was read", "cnt", n)
	}
}

func (d *Device) set_vring_enable(msg *UserMsg) error {
	state := msg.VRingState()
	d.vhostReady = state.Index > 0
	d.log.Info("vring enabled", "index", state.Index, "num", state.Num)

	virtq := d.virtq[state.Index]
	if virtq != nil && virtq.kickFD != 0 {
		if state.Index == 1 {
			d.log.Info("registered virtq as recv", "index", state.Index)
			d.recv = virtq
			//d.log.Info("starting goroutine to process kick requests")
			//go d.watchKick(virtq)
		} else {
			d.log.Info("registered virtq as txmit", "index", state.Index)
			d.xmit = virtq
		}
	}
	return nil
}

type Packet struct {
	buf bytes.Buffer
}

type PacketProcessor interface {
	IncomingPacket(dev *Device, pkt []byte) error
}

func (d *Device) bufFromGuest(addr uint64, sz uint32) ([]byte, error) {
	for _, e := range d.memTable {
		if e.contains(addr) {
			return e.Data[addr-e.Guest:][:sz], nil
		}
	}

	return nil, fmt.Errorf("mapping to host buffer failed: %d", addr)
}

func (d *Device) TransmitFrames(ctx context.Context, input ethswitch.TxFrameReturner) (int, error) {
	var cnt int

	v := d.xmit

	for {
		buffers, d_idx, err := d.getNextBuffer(v, &d.xmitBuffers)
		if err != nil {
			return cnt, errors.Wrapf(err, "sending test packet")
		}

		if buffers == nil {
			return cnt, nil
		}

		buf := buffers[0]

		f, ok := input.PopTxFrame()
		if !ok {
			return cnt, nil
		}

		frame := f.Data

		if len(frame) > len(buf) {
			return cnt, fmt.Errorf("jumbo frames not implemented yet")
		}

		buf = buf[:10+len(frame)]
		clear(buf[:10])
		copy(buf[10:], frame)

		buffers[0] = buf

		d.log.Trace("gpv6: transmitting frame", "size", len(buf))

		d.returnBuffer(v, buffers, d_idx)
		d.signalUsed(v)
	}
}

func (d *Device) driveTx(ctx context.Context) error {
	v := d.xmit

	d.log.Info("tx loop started")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-d.txcharge:
			// ok
		}

		var used int

		for !d.txBuf.EmptyP() {
		retry:
			buffers, d_idx, err := d.getNextBuffer(v, &d.xmitBuffers)
			if err != nil {
				return errors.Wrapf(err, "sending test packet")
			}

			if buffers == nil {
				time.Sleep(time.Microsecond)
				goto retry
			}

			qf, ok := d.txBuf.Pop()
			if !ok {
				break
			}

			d.useBuffer(v, buffers, d_idx, qf)
			used++

			qf.Discard(d.log)

			if used > 50 {
				d.signalUsed(v)
			}
		}

		d.signalUsed(v)
	}
}

func (d *Device) TransmitFrame(ctx context.Context, input *ethswitch.Frame) error {
	if len(input.Data) > 1600 {
		return fmt.Errorf("jumbo frames not implemented yet")
	}

	input.IncRef(1)

retry:
	if d.txBuf.Push(input) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case d.txcharge <- struct{}{}:
			// ok
		}
	} else {
		time.Sleep(50 * time.Microsecond)
		goto retry
	}

	return nil
}

func (d *Device) TransmitFramex(ctx context.Context, input *ethswitch.Frame) error {
	if len(input.Data) > 1600 {
		return fmt.Errorf("jumbo frames not implemented yet")
	}

	v := d.xmit

retry:

	buffers, d_idx, err := d.getNextBuffer(v, &d.xmitBuffers)
	if err != nil {
		return errors.Wrapf(err, "sending test packet")
	}

	if buffers == nil {
		time.Sleep(time.Microsecond)

		goto retry
		/*
			if d.txBuf.FullP() {
				goto retry
			}

			d.txBuf.Push(input)
			return nil
		*/
	}

	/*
		if !d.txBuf.EmptyP() {
			qf, ok := d.txBuf.Pop()
			if ok {
				d.useBuffer(v, buffers, d_idx, qf)
			}
			goto retry
		}
	*/

	d.useBuffer(v, buffers, d_idx, input)

	d.signalUsed(v)
	return nil
}

func (d *Device) useBuffer(v *Virtq, buffers [][]byte, d_idx uint16, fr *ethswitch.Frame) {
	buf := buffers[0]

	frame := fr.Data

	buf = buf[:10+len(frame)]
	clear(buf[:10])
	copy(buf[10:], frame)

	buffers[0] = buf

	if d.log.IsTrace() {
		d.log.Trace("gpv6: transmitted frame", "size", len(buf))
	}

	d.returnBuffer(v, buffers, d_idx)
}

type buffers struct {
	data [][]byte
}

func (d *Device) getNextBuffer(v *Virtq, b *buffers) ([][]byte, uint16, error) {
	for !d.bufLock.CompareAndSwap(0, 1) {
		// spin loop!
	}

	desc := v.ring.desc
	avail := v.ring.avail

	if v.last_avail_idx == uint32(avail.Idx()) {
		d.bufLock.Store(0)
		return nil, 0, nil
	}

	d_idx := avail.Ring(v.last_avail_idx % v.num)

	buf, err := d.bufFromGuest(
		desc.Addr(int(d_idx)),
		desc.Len(int(d_idx)),
	)
	if err != nil {
		d.bufLock.Store(0)
		d.log.Error("error retrieving buffer", "error", err, "idx", d_idx)
		return nil, 0, err
	}

	ret := b.data[:0]

	ret = append(ret, buf)

	header := d_idx

	for desc.Flags(int(d_idx))&VIRTIO_DESC_F_NEXT != 0 {
		d_idx = desc.Next(int(d_idx))

		sub, err := d.bufFromGuest(
			desc.Addr(int(d_idx)),
			desc.Len(int(d_idx)),
		)
		if err != nil {
			d.bufLock.Store(0)
			return nil, 0, err
		}

		ret = append(ret, sub)
	}

	v.last_avail_idx = (v.last_avail_idx + 1) & math.MaxUint16

	b.data = ret[:0]

	d.bufLock.Store(0)
	return ret, header, nil
}

func (d *Device) returnBuffer(v *Virtq, buffers [][]byte, idx uint16) {
	var dlen uint32

	for _, b := range buffers {
		dlen += uint32(len(b))
	}

	v.ring.used.SetRing(int(v.last_used_idx%v.num), uint32(idx), dlen)
	v.last_used_idx = (v.last_used_idx + 1) & math.MaxUint16
}

func (d *Device) signalUsed(v *Virtq) {
	if v.ring.used.Idx() != uint16(v.last_used_idx) {
		v.ring.used.SetIdx(uint16(v.last_used_idx))
		//unix.Msync(v.ring.used.data, unix.MS_SYNC|unix.MS_INVALIDATE)
		unix.Write(v.callFD, kickBuf)
	}
}
