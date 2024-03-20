package vhostuser

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type NetDevice struct {
}

func NewNetDevice() (*NetDevice, error) {
	nd := &NetDevice{}

	return nd, nil
}

func (n *NetDevice) IncomingPacket(d *Device, data []byte) error {
	spew.Dump(data)

	pktData := data[virtio_net_hdr_size:]
	pkt := gopacket.NewPacket(pktData, layers.LayerTypeEthernet, gopacket.Default)
	spew.Dump(data[:virtio_net_hdr_size])
	fmt.Println(pkt.Dump())

	d.log.Trace("echoing packet back in netdevice")

	/*
		err := d.Transmit(pktData)
		if err != nil {
			d.log.Error("error putting packet back", "error", err)
		}
	*/

	return nil
}
