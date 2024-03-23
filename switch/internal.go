package ethswitch

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"

	"github.com/davecgh/go-spew/spew"
	"github.com/lab47/lnf/pkg/lldp"
	"github.com/mdlayher/ethernet"
)

type InternalPort struct {
	sw *Switch

	xmit func(frame []byte) error
}

var be = binary.BigEndian

func (i *InternalPort) TransmitFrame(ctx context.Context, frame *Frame) error {
	ethType := frame.Data[12:14]

	i.sw.log.Trace("handling frame on internal port", "ethType", ethType)

	switch be.Uint16(ethType) {
	case uint16(lldp.EtherType):
		return i.handleLLDP(ctx, frame)
	}
	return nil
}

func (i *InternalPort) ReceiveFrame(ctx context.Context, fn func(frame []byte) error) error {
	i.xmit = fn
	return nil
}

func (i *InternalPort) handleLLDP(_ context.Context, frame *Frame) error {
	var ef ethernet.Frame

	err := ef.UnmarshalBinary(frame.Data)
	if err != nil {
		return err
	}

	var lf lldp.Frame

	err = lf.UnmarshalBinary(ef.Payload)
	if err != nil {
		return err
	}

	pm := PortMetadata{}

	switch lf.PortID.Subtype {
	case lldp.PortIDSubtypeMACAddress:
		pm.PortId = net.HardwareAddr(lf.PortID.ID).String()
	case
		lldp.PortIDSubtypeInterfaceName,
		lldp.PortIDSubtypeInterfaceAlias:

		pm.PortId = string(lf.PortID.ID)
	}

	for _, val := range lf.Optional {
		switch val.Type {
		case lldp.TLVTypeSystemName:
			pm.SystemName = string(val.Value)
		case lldp.TLVTypeManagementAddress:
			alen := val.Value[0]
			addr := val.Value[2 : alen+1]

			if ip, ok := netip.AddrFromSlice(addr); ok {
				pm.ManagementAddresses = append(pm.ManagementAddresses, ip)
			}
		case lldp.TLVTypePortDescription:
			pm.Description = string(val.Value)
		}

	}

	sp := frame.SourcePort
	if sp.Metadata == nil {
		spew.Dump(pm)
	}

	frame.SourcePort.Metadata = &pm
	return nil
}
