package multiplex

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDatagramBuffer_RW(t *testing.T) {
	b := []byte{0x01, 0x02, 0x03}
	t.Run("simple write", func(t *testing.T) {
		pipe := NewDatagramBufferedPipe()
		_, err := pipe.Write(&Frame{Payload: b})
		assert.NoError(t, err)
	})

	t.Run("simple read", func(t *testing.T) {
		pipe := NewDatagramBufferedPipe()
		_, _ = pipe.Write(&Frame{Payload: b})
		b2 := make([]byte, len(b))
		n, err := pipe.Read(b2)
		assert.NoError(t, err)
		assert.Equal(t, len(b), n)
		assert.Equal(t, b, b2)
		assert.Equal(t, 0, pipe.buf.Len(), "buf len is not 0 after finished reading")
	})

	t.Run("writing closing frame", func(t *testing.T) {
		pipe := NewDatagramBufferedPipe()
		toBeClosed, err := pipe.Write(&Frame{Closing: closingStream})
		assert.NoError(t, err)
		assert.True(t, toBeClosed, "should be to be closed")
		assert.True(t, pipe.closed, "pipe should be closed")
	})
}

func TestDatagramBuffer_BlockingRead(t *testing.T) {
	pipe := NewDatagramBufferedPipe()
	b := []byte{0x01, 0x02, 0x03}
	go func() {
		time.Sleep(readBlockTime)
		pipe.Write(&Frame{Payload: b})
	}()
	b2 := make([]byte, len(b))
	n, err := pipe.Read(b2)
	assert.NoError(t, err)
	assert.Equal(t, len(b), n, "number of bytes read after block is wrong")
	assert.Equal(t, b, b2)
}

func TestDatagramBuffer_CloseThenRead(t *testing.T) {
	pipe := NewDatagramBufferedPipe()
	b := []byte{0x01, 0x02, 0x03}
	pipe.Write(&Frame{Payload: b})
	b2 := make([]byte, len(b))
	pipe.Close()
	n, err := pipe.Read(b2)
	assert.NoError(t, err)
	assert.Equal(t, len(b), n, "number of bytes read after block is wrong")
	assert.Equal(t, b, b2)
}
