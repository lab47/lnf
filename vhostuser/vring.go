package vhostuser

import "encoding/binary"

// Size of vring structures used in Linux vhost. Max 32768.
const VHOST_VRING_SIZE = 1024

// vring_desc I/O buffer descriptor
type VRingDesc struct {
	addr  uint64 // packet data buffer address
	len   uint32 // packet data buffer size
	flags uint16 // (see below)
	next  uint16 // optional index next descriptor in chain
}

const descSize = 8 + 4 + (2 * 2)

// Available vring_desc.flags
const (
	VIRTIO_DESC_F_NEXT     = 1 // Descriptor continues via 'next' field
	VIRTIO_DESC_F_WRITE    = 2 // Write-only descriptor (otherwise read-only)
	VIRTIO_DESC_F_INDIRECT = 4 // Buffer contains a list of descriptors
)

const ( // flags for avail and used rings
	VRING_F_NO_INTERRUPT  = 1  // Hint: don't bother to call process
	VRING_F_NO_NOTIFY     = 1  // Hint: don't bother to kick kernel
	VRING_F_INDIRECT_DESC = 28 // Indirect descriptors are supported
	VRING_F_EVENT_IDX     = 29 // (Some boring complicated interrupt behavior..)
)

type DescArrayAccess struct {
	data []byte
}

func (d *DescArrayAccess) nth(n int) []byte {
	return d.data[n*descSize:]
}

func (d *DescArrayAccess) Addr(n int) uint64 {
	return binary.NativeEndian.Uint64(d.nth(n))
}

func (d *DescArrayAccess) Len(n int) uint32 {
	return binary.NativeEndian.Uint32(d.nth(n)[8:])
}

func (d *DescArrayAccess) SetLen(n int, l uint32) {
	binary.NativeEndian.PutUint32(d.nth(n)[8:], l)
}

func (d *DescArrayAccess) Flags(n int) uint16 {
	return binary.NativeEndian.Uint16(d.nth(n)[12:])
}

func (d *DescArrayAccess) SetFlags(n int, f uint16) {
	binary.NativeEndian.PutUint16(d.nth(n)[12:], f)
}

func (d *DescArrayAccess) Next(n int) uint16 {
	return binary.NativeEndian.Uint16(d.nth(n)[14:])
}

func (d *DescArrayAccess) SetNext(n int, v uint16) {
	binary.NativeEndian.PutUint16(d.nth(n)[14:], v)
}

// ring of descriptors that are available to be processed
type VRingAvail struct {
	flags uint16
	idx   uint16
	ring  [VHOST_VRING_SIZE]uint16
}

type AvailAccess struct {
	data []byte
}

func (u *AvailAccess) Flags() uint16 {
	return binary.NativeEndian.Uint16(u.data)
}

func (u *AvailAccess) Idx() uint16 {
	return binary.NativeEndian.Uint16(u.data[2:])
}

func (u *AvailAccess) SetIdx(v uint16) {
	binary.NativeEndian.PutUint16(u.data[2:], v)
}

func (u *AvailAccess) Ring(n uint32) uint16 {
	return binary.NativeEndian.Uint16(u.data[4+(n*2):])
}

func (u *AvailAccess) SetRing(n uint32, v uint16) {
	binary.NativeEndian.PutUint16(u.data[4+(n*2):], v)
}

type VRingUsedElem struct {
	id  uint32
	len uint32
}

// ring of descriptors that have already been processed
type VRingUsed struct {
	Flags uint16
	Idx   uint16

	//Ring [VHOST_VRING_SIZE]VRingUsedElem
}

type UsedAccess struct {
	data []byte
}

func (u *UsedAccess) Flags() uint16 {
	return binary.NativeEndian.Uint16(u.data)
}

func (u *UsedAccess) SetFlags(f uint16) {
	binary.NativeEndian.PutUint16(u.data, f)
}

func (u *UsedAccess) SetIdx(idx uint16) {
	binary.NativeEndian.PutUint16(u.data[2:], idx)
}

func (u *UsedAccess) Idx() uint16 {
	return binary.NativeEndian.Uint16(u.data[2:])
}

func (u *UsedAccess) Ring(n int) (uint32, uint32) {
	ent := u.data[4+(n*8):]

	return binary.NativeEndian.Uint32(ent), binary.BigEndian.Uint32(ent[4:])
}

func (u *UsedAccess) SetRing(n int, id, ln uint32) {
	ent := u.data[4+(n*8):]

	binary.NativeEndian.PutUint32(ent, id)
	binary.NativeEndian.PutUint32(ent[4:], ln)
}
