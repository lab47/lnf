package vhostuser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/lab47/lnf/pkg/lldp"
	"github.com/lab47/lsvd/logger"
	"github.com/mdlayher/ethernet"
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

	/*
	   union {
	       uint64_t u64;
	       // defined in vhost.h
	       struct vhostu_vring_state state;
	       struct vhostu_vring_addr addr;
	       struct vhost_user_memory memory;
	   };
	*/
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

	memTable []*MemoryTableEntry
	xmit     *Virtq

	pp PacketProcessor
}

func NewDevice(log logger.Logger, conn *net.UnixConn, pp PacketProcessor) *Device {
	d := &Device{
		log:  log,
		conn: conn,
		buf:  make([]byte, 1024*10),
		obuf: make([]byte, 1024*10),
		pp:   pp,
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
}

func (v *Virtq) put_buffer(header_id uint16, total_size uint32) {
	v.ring.used.SetRing(int(v.last_used_idx&v.num-1), uint32(header_id), total_size)

	v.last_used_idx = (v.last_used_idx + 1) & math.MaxUint16
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

func (d *Device) Process() error {
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

		/*
			err = unix.Close(fd)
			if err != nil {
				d.log.Warn("error closing mmap fd", "error", err)
			}
		*/

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

/*

mapped address 139741475729408 => 140167157760000 (base=140167071940608, user=139741389910016
mapped address 139741475733504 => 140167157764096 (base=140167071940608, user=139741389910016
mapped address 139741475737600 => 140167157768192 (base=140167071940608, user=139741389910016

*/

func (d *Device) mapFromQemu(addr uint64) []byte {
	for _, e := range d.memTable {
		if e.containsQemu(addr) {
			dpdk := addr + e.Guest + uint64(e.MappedAddress) - e.Qemu
			//va := addr + e.Guest + e.Offset - e.Qemu
			offset := addr - e.Qemu
			d.log.Trace("mapped address from qemu", "addr", addr,
				"region", e.Qemu, "region-size", e.DataSize, "offset", offset,
				"dpdk", dpdk, "dpdk-offset", dpdk-uint64(e.MappedAddress),
			)

			//used := (*VRingUsed)(unsafe.Pointer(uintptr(dpdk)))

			//spew.Dump(used)
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

func (d *Device) set_vring_enable(msg *UserMsg) error {
	state := msg.VRingState()
	d.vhostReady = state.Index > 0
	d.log.Info("vring enabled", "index", state.Index, "num", state.Num)

	virtq := d.virtq[state.Index]
	if virtq != nil && virtq.kickFD != 0 {
		if state.Index == 1 {
			d.log.Info("starting goroutine to process kick requests")
			go d.watchKick(virtq)
		} else {
			d.log.Info("registered virtq as txmit", "index", state.Index)
			d.xmit = virtq
		}
	}
	return nil
}

func (d *Device) watchKick(v *Virtq) {
	buf := make([]byte, 8)

	f := os.NewFile(uintptr(v.kickFD), "kick")

	for {
		n, err := f.Read(buf)
		if err != nil {
			d.log.Error("reading kick failed", "error", err)
			return
		}

		d.log.Trace("kick was read", "cnt", n)

		err = d.getPackets(v, d.pp, 0)
		if err != nil {
			d.log.Error("error handling packets", "error", err)
		}
	}
}

func (d *Device) receivePackets(pp PacketProcessor, hdr_len uint32) error {
	for i := 0; i < int(d.virtq_pairs); i++ {
		ring_id := 2*i + 1
		virtq := d.virtq[ring_id]

		err := d.getPackets(virtq, pp, hdr_len)
		if err != nil {
			return err
		}
	}

	return nil
}

/*
-- Receive all available packets from the virtual machine.
function VirtioVirtq:get_buffers (kind, ops, hdr_len)

	local device = self.device
	local idx = self.virtq.avail.idx
	local avail, vring_mask = self.avail, self.vring_num-1

	while idx ~= avail do

	   -- Header
	   local v_header_id = self.virtq.avail.ring[band(avail,vring_mask)]
	   local desc, id = self:get_desc(v_header_id)

	   local data_desc = desc[id]

	   local packet =
	      ops.packet_start(device, data_desc.addr, data_desc.len)
	   local total_size = hdr_len

	   if not packet then break end

	   -- support ANY_LAYOUT
	   if hdr_len < data_desc.len then
	      local addr = data_desc.addr + hdr_len
	      local len = data_desc.len - hdr_len
	      local added_len = ops.buffer_add(device, packet, addr, len)
	      total_size = total_size + added_len
	   end

	   -- Data buffer
	   while band(data_desc.flags, C.VIRTIO_DESC_F_NEXT) ~= 0 do
	      data_desc  = desc[data_desc.next]
	      local added_len = ops.buffer_add(device, packet, data_desc.addr, data_desc.len)
	      total_size = total_size + added_len
	   end

	   ops.packet_end(device, v_header_id, total_size, packet)

	   avail = band(avail + 1, 65535)
	end
	self.avail = avail

end
*/

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

func (d *Device) getPackets(v *Virtq, pp PacketProcessor, hdr_len uint32) error {
	buffers, d_idx, err := d.getNextBuffer(v)
	if err != nil {
		return err
	}

	buf := buffers[0]

	d.log.Trace("gpv4: packet read", "size", len(buf))

	data := buf[virtio_net_hdr_size:]
	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	fmt.Println(pkt.Dump())

	d.returnBuffer(v, buffers, d_idx)
	d.signalUsed(v)

	return d.sendTestPacket()
}

var (
	lldpDest net.HardwareAddr
	noSrc    net.HardwareAddr
)

func init() {
	lldpDest, _ = net.ParseMAC("01:80:c2:00:00:0e")
	noSrc, _ = net.ParseMAC("00:00:00:00:00:00")
}

func (d *Device) sendTestPacket() error {
	v := d.xmit

	lfr := lldp.Frame{
		ChassisID: &lldp.ChassisID{
			Subtype: lldp.ChassisIDSubtypeInterfaceName,
			ID:      []byte("sys0"),
		},
		PortID: &lldp.PortID{
			Subtype: lldp.PortIDSubtypeInterfaceName,
			ID:      []byte("lnf0"),
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

	buffers, d_idx, err := d.getNextBuffer(v)
	if err != nil {
		return errors.Wrapf(err, "sending test packet")
	}

	buf := buffers[0]

	buf = buf[:10+len(pktData)]
	clear(buf[:10])
	copy(buf[10:], pktData)

	buffers[0] = buf

	d.log.Trace("gpv4: test lldp packet write", "size", len(buf))

	d.returnBuffer(v, buffers, d_idx)
	d.signalUsed(v)

	return nil
}

func (d *Device) getPackets2(v *Virtq, pp PacketProcessor, hdr_len uint32) error {
	avail := v.ring.avail
	used := v.ring.used
	num := v.num

	a_idx := v.last_avail_idx % num

	for v.last_avail_idx != uint32(avail.Idx()) {

		d.process_desc(v, a_idx, pp, hdr_len)

		a_idx = (a_idx + 1) % num
		v.last_avail_idx++
		v.last_used_idx++
	}

	used.SetIdx(uint16(v.last_used_idx))
	unix.Msync(used.data, unix.MS_SYNC|unix.MS_INVALIDATE)

	if avail.Flags()&VRING_F_NO_INTERRUPT == 0 {
		d.log.Trace("signaling used")
		unix.Write(v.callFD, kickBuf)
	}

	return nil
}

/* Frame (60 bytes) */
var arp_request = [...]byte{0xff, 0xff, 0xff, 0xff, 0xff,
	0xff,                               /* DST MAC - broadcast */
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, /* SRC MAC -01:02:03:04:05:06 */
	0x08, 0x06, /* Eth Type - ARP */
	0x00, 0x01, /* Ethernet */
	0x08, 0x00, /* Protocol - IP */
	0x06,       /* HW size */
	0x04,       /* Protocol size */
	0x00, 0x01, /* Request */
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, /* Sender MAC */
	0xc0, 0xa8, 0x00, 0x02, /* Sender IP - 192.168.0.2*/
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Target MAC */
	0xc0, 0xa8, 0x00, 0x01, /* Target IP - 192.168.0.1*/
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Padding */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

func (d *Device) getNextBuffer(v *Virtq) ([][]byte, uint16, error) {
	desc := v.ring.desc
	avail := v.ring.avail

	if v.last_avail_idx == uint32(avail.Idx()) {
		return nil, 0, fmt.Errorf("no buffers available")
	}

	d_idx := avail.Ring(v.last_avail_idx % v.num)

	buf, err := d.bufFromGuest(
		desc.Addr(int(d_idx)),
		desc.Len(int(d_idx)),
	)
	if err != nil {
		return nil, 0, err
	}

	var ret [][]byte

	ret = append(ret, buf)

	header := d_idx

	for desc.Flags(int(d_idx))&VIRTIO_DESC_F_NEXT != 0 {
		d_idx = desc.Next(int(d_idx))

		sub, err := d.bufFromGuest(
			desc.Addr(int(d_idx)),
			desc.Len(int(d_idx)),
		)
		if err != nil {
			return nil, 0, err
		}

		ret = append(ret, sub)
	}

	v.last_avail_idx = (v.last_avail_idx + 1) & math.MaxUint16

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
		unix.Msync(v.ring.used.data, unix.MS_SYNC|unix.MS_INVALIDATE)
		unix.Write(v.callFD, kickBuf)
	}
}

func (d *Device) process_desc(v *Virtq, a_idx uint32, pp PacketProcessor, _ uint32) error {
	desc := v.ring.desc
	avail := v.ring.avail
	used := v.ring.used

	d_idx := avail.Ring(a_idx)

	i := d_idx

	var output bytes.Buffer

	var llen uint32 = 0

	for {
		d.log.Trace("process desc", "a_idx", a_idx, "i", i)

		cur_len := desc.Len(int(i))

		buf, err := d.bufFromGuest(desc.Addr(int(i)), cur_len)
		if err != nil {
			return err
		}

		output.Write(buf)

		llen += cur_len

		if desc.Flags(int(i))&VIRTIO_DESC_F_NEXT != 0 {
			i = desc.Next(int(i))
		} else {
			break
		}
	}

	if llen == 0 {
		return nil
	}

	num := v.num
	u_idx := v.last_used_idx % num
	used.SetRing(int(u_idx), uint32(d_idx), llen)

	d.log.Trace("packet read", "size", output.Len())

	data := output.Bytes()[virtio_net_hdr_size:]
	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	fmt.Println(pkt.Dump())

	if d.xmit != nil {
		d.log.Trace("echoing packet back")

		err := d.put_vring(d.xmit, arp_request[:])
		if err != nil {
			d.log.Error("error putting packet back", "error", err)
		}
	}

	return nil
}

func (d *Device) put_vring(v *Virtq, data []byte) error {
	desc := v.ring.desc
	avail := v.ring.avail
	used := v.ring.used

	num := v.num

	a_idx := v.last_avail_idx

	d_idx := avail.Ring(a_idx)

	dlen := desc.Len(int(d_idx))

	if len(data) > int(dlen) {
		return fmt.Errorf("descriptor too small %d < %d", dlen, len(data))
	}

	//v.last_avail_idx = uint32(desc.Next(int(a_idx)))

	buf, err := d.bufFromGuest(desc.Addr(int(d_idx)), dlen)
	if err != nil {
		return err
	}

	v.last_avail_idx = (a_idx + 1) & math.MaxUint16

	clear(buf[:10])
	copy(buf[10:], data)

	desc.SetLen(int(a_idx), uint32(10+len(data)))
	desc.SetFlags(int(a_idx), 0)
	desc.SetNext(int(a_idx), math.MaxUint16)

	avail.SetRing(uint32(avail.Idx())%num, uint16(a_idx))
	avail.SetIdx(avail.Idx() + 1)

	unix.Msync(avail.data, unix.MS_SYNC|unix.MS_INVALIDATE)
	unix.Msync(buf, unix.MS_SYNC|unix.MS_INVALIDATE)

	u_idx := v.last_used_idx % num
	v.last_used_idx = (u_idx + 1) & math.MaxUint16

	used.SetRing(int(u_idx), a_idx, uint32(10+len(data)))
	used.SetIdx(uint16(u_idx))
	unix.Msync(used.data, unix.MS_SYNC|unix.MS_INVALIDATE)

	unix.Write(v.callFD, kickBuf)
	unix.Fsync(v.callFD)

	unix.Write(v.kickFD, kickBuf)
	unix.Fsync(v.kickFD)

	return nil
}

var kickBuf = make([]byte, 8)

func init() {
	binary.NativeEndian.PutUint64(kickBuf, 1)
}

/*
func (d *Device) getPackets2(v *Virtq, pp PacketProcessor, hdr_len uint32) error {
	//local idx = self.virtq.avail.idx
	idx := uint32(v.ring.avail.Idx())

	//local avail, vring_mask = self.avail, self.vring_num-1
	avail := v.last_avail_idx
	vring_mask := v.num - 1

	d.log.Trace("processing data in ring", "idx", idx, "avail", avail, "num", v.num)
	for idx != avail {
		//-- Header
		//local v_header_id = self.virtq.avail.ring[band(avail,vring_mask)]
		header_id := v.ring.avail.Ring(avail & vring_mask)
		//local desc, id = self:get_desc(v_header_id)

		data_addr := v.ring.desc.Addr(int(header_id))
		data_len := v.ring.desc.Len(int(header_id))
		//data_desc := v.ring.desc[header_id]

		//local data_desc = desc[id]
		//data_desc := desc.flags

		d.log.Trace("reading data", "idx", idx, "id", header_id, "addr", data_addr, "len", data_len)

		buf, err := d.bufFromGuest(data_addr, data_len)
		if err != nil {
			return err
		}

		packet, err := pp.PacketStart(buf)
		if err != nil {
			return err
		}

		if packet == nil {
			break
		}

		total_size := hdr_len

		if hdr_len < data_len {
			addr := data_addr + uint64(hdr_len)
			sz := data_len - hdr_len

			buf, err := d.bufFromGuest(addr, sz)
			if err != nil {
				return err
			}

			added_len, err := pp.BufferAdd(packet, buf)
			if err != nil {
				return err
			}

			total_size += added_len
		}

		flags := v.ring.desc.Flags(int(header_id))
		next := v.ring.desc.Next(int(header_id))

		for flags&VIRTIO_DESC_F_NEXT != 0 {
			//data_desc := v.ring.desc[data_desc.next]
			data_addr := v.ring.desc.Addr(int(next))
			data_len := v.ring.desc.Len(int(next))

			buf, err := d.bufFromGuest(data_addr, data_len)
			if err != nil {
				return err
			}

			added_len, err := pp.BufferAdd(packet, buf)
			if err != nil {
				return err
			}

			total_size += added_len

			flags = v.ring.desc.Flags(int(next))
			next = v.ring.desc.Next(int(next))
		}

		pp.PacketEnd(packet, header_id, total_size)

		v.ring.used.SetRing(int(idx), uint32(header_id), total_size)
		//v.put_buffer(header_id, total_size)

		avail = (avail + 1) & math.MaxUint16 // loop back to 0
	}

	v.last_avail_idx = avail

	return nil
}

*/
