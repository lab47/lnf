package ethswitch

import (
	"context"
	"sync/atomic"
	"time"

	ringbuf "github.com/lab47/lnf/pkg/ring_buf"
	"github.com/lab47/lsvd/logger"
)

type TxFrameReturner interface {
	PopTxFrame() (*Frame, bool)
}

type BufferedPortDevice interface {
	PortDevice
	ReceiveFrame(ctx context.Context, fn func(frame []byte) error) error
	TransmitFrames(ctx context.Context, framer TxFrameReturner) (int, error)
}

type BufferedPort struct {
	log logger.Logger
	dev BufferedPortDevice

	txbuf *ringbuf.RingBuf[*Frame]
	rxbuf *ringbuf.RingBuf[*Frame]

	recv func(frame []byte) error

	txtick   *time.Ticker
	txcharge chan struct{}

	txframes atomic.Int64
	txbytes  atomic.Int64

	droptx atomic.Int64
	droprx atomic.Int64
}

func NewBufferedPort(ctx context.Context, log logger.Logger, sz int, dev BufferedPortDevice) *BufferedPort {
	bp := &BufferedPort{
		log:      log,
		dev:      dev,
		txbuf:    ringbuf.NewRingBuf[*Frame](sz),
		rxbuf:    ringbuf.NewRingBuf[*Frame](sz),
		txtick:   time.NewTicker(10 * time.Millisecond),
		txcharge: make(chan struct{}, 100),
	}

	go bp.pollTX(ctx)

	return bp
}

func (b *BufferedPort) ReceiveFrame(ctx context.Context, fn func(frame []byte) error) error {
	return b.dev.ReceiveFrame(ctx, fn)
}

func (b *BufferedPort) oldReceiveFrame(ctx context.Context, fn func(frame []byte) error) error {
	sig := make(chan struct{}, 10)
	tick := time.NewTicker(time.Second)

	go func() {
		defer tick.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-sig:
			//ok
			case <-tick.C:
				//ok
			}

			for {
				if frame, ok := b.rxbuf.Pop(); ok {
					err := fn(frame.Data)
					frame.Discard(b.log)
					if err != nil {
						b.log.Error("error training rxbuf", "error", err)
					}
				} else {
					break
				}
			}
		}
	}()

	return b.dev.ReceiveFrame(ctx, func(frame []byte) error {
		if !b.rxbuf.Push(NewFrame(frame, nil)) {
			b.droprx.Add(1)
		}

		return nil
	})
}

func (b *BufferedPort) TransmitFrame(ctx context.Context, frame *Frame) error {
	if !b.txbuf.Push(frame) {
		b.droptx.Add(1)
		return nil
	}

	b.txcharge <- struct{}{}

	return nil
}

func (b *BufferedPort) PopTxFrame() (*Frame, bool) {
	frame, ok := b.txbuf.Pop()
	if !ok {
		return nil, false
	}

	b.log.Trace("popped buffered frame")

	b.txframes.Add(1)
	b.txbytes.Add(int64(len(frame.Data)))

	return frame, true
}

func (b *BufferedPort) pollTX(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-b.txtick.C:
			//ok

		case <-b.txcharge:
			//ok
		}

		for {
			cnt, err := b.dev.TransmitFrames(ctx, b)
			if err != nil {
				b.log.Error("error transmitting frames", "error", err)
			}

			if cnt == 0 {
				break
			} else {
				b.log.Trace("transmitted frames", "count", cnt)
			}
		}
	}
}
