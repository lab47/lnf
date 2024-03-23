package ethswitch

import (
	"context"

	"github.com/lab47/lnf/pkg/tap"
	"github.com/lab47/lsvd/logger"
)

type TapPort struct {
	log   logger.Logger
	iface *tap.Interface
}

func OpenTapPort(log logger.Logger, name string) (*TapPort, error) {
	iface, err := tap.Open(name)
	if err != nil {
		return nil, err
	}

	/*
		iface, err := water.New(water.Config{
			DeviceType: water.TAP,
			PlatformSpecificParams: water.PlatformSpecificParams{
				Name:    name,
				Persist: true,
			},
		})
		if err != nil {
			return nil, err
		}
	*/

	return &TapPort{log: log, iface: iface}, nil
}

func (t *TapPort) TransmitFrame(ctx context.Context, frame *Frame) error {
	t.log.Trace("transmitting frame to tap", "len", len(frame.Data))
	_, err := t.iface.Write(frame.Data)
	return err
}

func (t *TapPort) ReceiveFrame(ctx context.Context, fn func(frame []byte) error) error {
	frame := make([]byte, 2000)

	for {
		n, err := t.iface.Read(frame)
		if err != nil {
			return err
		}

		body := frame[:n]

		if t.log.IsTrace() {
			t.log.Trace("received tap frame", "len", len(body))
		}

		err = fn(body)
		if err != nil {
			return err
		}
	}
}
