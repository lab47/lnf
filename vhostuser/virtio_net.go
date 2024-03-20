package vhostuser

const (
	VIRTIO_NET_F_CSUM           = 1 << 0  /* Host handles pkts w/ partial csum */
	VIRTIO_NET_F_GUEST_CSUM     = 1 << 1  /* Guest handles pkts w/ partial csum */
	VIRTIO_NET_F_MTU            = 1 << 3  /* Initial MTU advice */
	VIRTIO_NET_F_MAC            = 1 << 5  /* Host has given MAC address. */
	VIRTIO_NET_F_GSO            = 1 << 6  /* Host handles pkts w/ any GSO type */
	VIRTIO_NET_F_GUEST_TSO4     = 1 << 7  /* Guest can handle TSOv4 in. */
	VIRTIO_NET_F_GUEST_TSO6     = 1 << 8  /* Guest can handle TSOv6 in. */
	VIRTIO_NET_F_GUEST_ECN      = 1 << 9  /* Guest can handle TSO[6] w/ ECN in. */
	VIRTIO_NET_F_GUEST_UFO      = 1 << 10 /* Guest can handle UFO in. */
	VIRTIO_NET_F_HOST_TSO4      = 1 << 11 /* Host can handle TSOv4 in. */
	VIRTIO_NET_F_HOST_TSO6      = 1 << 12 /* Host can handle TSOv6 in. */
	VIRTIO_NET_F_HOST_ECN       = 1 << 13 /* Host can handle TSO[6] w/ ECN in. */
	VIRTIO_NET_F_HOST_UFO       = 1 << 14 /* Host can handle UFO in. */
	VIRTIO_NET_F_MRG_RXBUF      = 1 << 15 /* Driver can merge receive buffers. */
	VIRTIO_NET_F_STATUS         = 1 << 16 /* Configuration status field is available. */
	VIRTIO_NET_F_CTRL_VQ        = 1 << 17 /* Control channel is available. */
	VIRTIO_NET_F_CTRL_RX        = 1 << 18 /* Control channel RX mode support. */
	VIRTIO_NET_F_CTRL_VLAN      = 1 << 19 /* Control channel VLAN filtering. */
	VIRTIO_NET_F_GUEST_ANNOUNCE = 1 << 21 /* Driver can send gratuitous packets. */
	VIRTIO_NET_F_MQ             = 1 << 22 /* Device supports Receive Flow
	 * Steering */
	VIRTIO_NET_F_CTRL_MAC_ADDR = 1 << 23 /* Set MAC address */
	VIRTIO_NET_F_VQ_NOTF_COAL  = 1 << 52 /* Device supports virtqueue notification coalescing */
	VIRTIO_NET_F_NOTF_COAL     = 1 << 53 /* Device supports notifications coalescing */
	VIRTIO_NET_F_GUEST_USO4    = 1 << 54 /* Guest can handle USOv4 in. */
	VIRTIO_NET_F_GUEST_USO6    = 1 << 55 /* Guest can handle USOv6 in. */
	VIRTIO_NET_F_HOST_USO      = 1 << 56 /* Host can handle USO in. */
	VIRTIO_NET_F_HASH_REPORT   = 1 << 57 /* Supports hash report */
	VIRTIO_NET_F_GUEST_HDRLEN  = 1 << 59 /* Guest provides the exact hdr_len value. */
	VIRTIO_NET_F_RSS           = 1 << 60 /* Supports RSS RX steering */
	VIRTIO_NET_F_RSC_EXT       = 1 << 61 /* extended coalescing info */
	VIRTIO_NET_F_STANDBY       = 1 << 62 /* Act as standby for another device
	 * with the same MAC.
	 */
	VIRTIO_NET_F_SPEED_DUPLEX = 1 < 63 /* Device set linkspeed and duplex */

	VIRTIO_NET_S_LINK_UP  = 1 /* Link is up */
	VIRTIO_NET_S_ANNOUNCE = 2 /* Announcement is needed */

	/* supported/enabled hash types */
	VIRTIO_NET_RSS_HASH_TYPE_IPv4   = (1 << 0)
	VIRTIO_NET_RSS_HASH_TYPE_TCPv4  = (1 << 1)
	VIRTIO_NET_RSS_HASH_TYPE_UDPv4  = (1 << 2)
	VIRTIO_NET_RSS_HASH_TYPE_IPv6   = (1 << 3)
	VIRTIO_NET_RSS_HASH_TYPE_TCPv6  = (1 << 4)
	VIRTIO_NET_RSS_HASH_TYPE_UDPv6  = (1 << 5)
	VIRTIO_NET_RSS_HASH_TYPE_IP_EX  = (1 << 6)
	VIRTIO_NET_RSS_HASH_TYPE_TCP_EX = (1 << 7)
	VIRTIO_NET_RSS_HASH_TYPE_UDP_EX = (1 << 8)
)
