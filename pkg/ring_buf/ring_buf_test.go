package ringbuf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRingBuf(t *testing.T) {
	t.Run("supports push/empty/pop", func(t *testing.T) {
		r := require.New(t)

		rb := NewRingBuf[int](10)
		r.True(rb.EmptyP())

		r.True(rb.Push(1))
		r.False(rb.EmptyP())

		v, ok := rb.Pop()
		r.True(ok)

		r.Equal(1, v)
		r.True(rb.EmptyP())

		r.True(rb.Push(2))
		r.False(rb.EmptyP())

		r.Equal(1, rb.Readable())
	})

	t.Run("can fill up", func(t *testing.T) {
		r := require.New(t)

		rb := NewRingBuf[int](3)
		r.True(rb.EmptyP())
		r.False(rb.FullP())

		rb.Push(1)
		r.False(rb.EmptyP())
		r.False(rb.FullP())

		rb.Push(2)
		r.False(rb.EmptyP())
		r.True(rb.FullP())
	})

	t.Run("loops around the ring", func(t *testing.T) {
		r := require.New(t)

		rb := NewRingBuf[int](5)
		r.True(rb.EmptyP())

		r.True(rb.Push(1))
		r.True(rb.Push(2))
		r.True(rb.Push(3))
		r.True(rb.Push(4))
		r.False(rb.EmptyP())

		_, ok := rb.Pop()
		r.True(ok)

		_, ok = rb.Pop()
		r.True(ok)

		r.False(rb.FullP())
		r.True(rb.Push(5))
		r.True(rb.Push(6))

		r.True(rb.FullP())

		r.Equal(4, rb.Readable())

		r.Equal(int32(2), rb.read.Load())
		r.Equal(int32(1), rb.write.Load())

		_, ok = rb.Pop()
		r.True(ok)

		_, ok = rb.Pop()
		r.True(ok)

		f, ok := rb.Pop()
		r.True(ok)
		r.Equal(5, f)

		s, ok := rb.Pop()
		r.True(ok)
		r.Equal(6, s)

		r.Equal(int32(1), rb.read.Load())
	})
}
