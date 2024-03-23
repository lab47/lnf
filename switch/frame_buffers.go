package ethswitch

import (
	"sync"
	"sync/atomic"

	"github.com/lab47/lsvd/logger"
)

type Frame struct {
	Ref        atomic.Int32
	Data       []byte
	SourcePort *Port
}

const FrameBufferSize = 2000

var frameBuffers = sync.Pool{
	New: func() any {
		return &Frame{
			Data: make([]byte, 0, FrameBufferSize),
		}
	},
}

func NewFrame(data []byte, src *Port) *Frame {
	fb := frameBuffers.Get().(*Frame)
	fb.Data = append(fb.Data[:0], data...)
	fb.SourcePort = src
	fb.Ref.Store(1)
	return fb
}

func (f *Frame) IncRef(cnt int32) {
	f.Ref.Add(cnt)
}

func (f *Frame) Discard(log logger.Logger) {
	ref := f.Ref.Add(-1)

	if ref == 0 {
		frameBuffers.Put(f)
	}
}
