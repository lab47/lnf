package vhostuser

type virtio_net_hdr struct {
	Flags       uint8 // See flags enum above
	Gso_type    uint8 // See GSO type above
	Hdr_len     uint16
	Gso_size    uint16
	Csum_start  uint16
	Csum_offset uint16
}

const virtio_net_hdr_size = 10

var zeroHdr = make([]byte, virtio_net_hdr_size)

type virtio_net_hdr_mrg_rxbuf struct {
	Hdr         virtio_net_hdr
	Num_buffers uint16
}

const virtio_net_hdr_mrg_rxbuf_size = virtio_net_hdr_size + 2
