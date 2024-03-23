package ringbuf

import (
	"sync/atomic"
)

type RingBuf[V any] struct {
	ring []V

	read, write atomic.Int32
}

func NewRingBuf[V any](sz int) *RingBuf[V] {
	return &RingBuf[V]{
		ring: make([]V, sz),
	}
}

func (r *RingBuf[V]) Pop() (V, bool) {
	rv := r.read.Load()
	wv := r.write.Load()

	if rv == wv {
		var v V
		return v, false
	}

	val := r.ring[rv]
	r.read.Store((rv + 1) % int32(len(r.ring)))

	return val, true
}

func (r *RingBuf[V]) Front() (V, bool) {
	rv := r.read.Load()
	wv := r.write.Load()

	if rv == wv {
		var v V
		return v, false
	}

	return r.ring[rv], true
}

func (r *RingBuf[V]) Push(v V) bool {
	if r.FullP() {
		return false
	}

	wv := r.write.Load()

	r.ring[wv] = v
	r.write.Store((wv + 1) % int32(len(r.ring)))

	return true
}

func (r *RingBuf[V]) EmptyP() bool {
	rv := r.read.Load()
	wv := r.write.Load()

	return rv == wv
}

func (r *RingBuf[V]) FullP() bool {
	rv := r.read.Load()
	wv := (r.write.Load() + 1) % int32(len(r.ring))

	return rv == wv
}

func (r *RingBuf[V]) Readable() int {
	rv := r.read.Load()
	wv := r.write.Load()

	if rv > wv {
		return int(wv + int32(len(r.ring)) - rv)
	}

	return int(wv - rv)
}
