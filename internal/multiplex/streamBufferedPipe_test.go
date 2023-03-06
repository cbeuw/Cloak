package multiplex

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const readBlockTime = 500 * time.Millisecond

func TestPipeRW(t *testing.T) {
	pipe := NewStreamBufferedPipe()
	b := []byte{0x01, 0x02, 0x03}
	n, err := pipe.Write(b)
	assert.NoError(t, err, "simple write")
	assert.Equal(t, len(b), n, "number of bytes written")

	b2 := make([]byte, len(b))
	n, err = pipe.Read(b2)
	assert.NoError(t, err, "simple read")
	assert.Equal(t, len(b), n, "number of bytes read")

	assert.Equal(t, b, b2)
}

func TestReadBlock(t *testing.T) {
	pipe := NewStreamBufferedPipe()
	b := []byte{0x01, 0x02, 0x03}
	go func() {
		time.Sleep(readBlockTime)
		pipe.Write(b)
	}()
	b2 := make([]byte, len(b))
	n, err := pipe.Read(b2)
	assert.NoError(t, err, "blocked read")
	assert.Equal(t, len(b), n, "number of bytes read after block")

	assert.Equal(t, b, b2)
}

func TestPartialRead(t *testing.T) {
	pipe := NewStreamBufferedPipe()
	b := []byte{0x01, 0x02, 0x03}
	pipe.Write(b)
	b1 := make([]byte, 1)
	n, err := pipe.Read(b1)
	assert.NoError(t, err, "partial read of 1")
	assert.Equal(t, len(b1), n, "number of bytes in partial read of 1")

	assert.Equal(t, b[0], b1[0])

	b2 := make([]byte, 2)
	n, err = pipe.Read(b2)
	assert.NoError(t, err, "partial read of 2")
	assert.Equal(t, len(b2), n, "number of bytes in partial read of 2")

	assert.Equal(t, b[1:], b2)
}

func TestReadAfterClose(t *testing.T) {
	pipe := NewStreamBufferedPipe()
	b := []byte{0x01, 0x02, 0x03}
	pipe.Write(b)
	b2 := make([]byte, len(b))
	pipe.Close()
	n, err := pipe.Read(b2)
	assert.NoError(t, err, "simple read")
	assert.Equal(t, len(b), n, "number of bytes read")

	assert.Equal(t, b, b2)
}

func BenchmarkBufferedPipe_RW(b *testing.B) {
	const PAYLOAD_LEN = 1000
	testData := make([]byte, PAYLOAD_LEN)
	rand.Read(testData)

	pipe := NewStreamBufferedPipe()

	smallBuf := make([]byte, PAYLOAD_LEN-10)
	go func() {
		for {
			pipe.Read(smallBuf)
		}
	}()
	b.SetBytes(int64(len(testData)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pipe.Write(testData)
	}
}
