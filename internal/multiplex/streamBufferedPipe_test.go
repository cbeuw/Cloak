package multiplex

import (
	"bytes"
	"math/rand"
	"testing"
	"time"
)

func TestPipeRW(t *testing.T) {
	pipe := NewStreamBufferedPipe()
	b := []byte{0x01, 0x02, 0x03}
	n, err := pipe.Write(b)
	if n != len(b) {
		t.Error(
			"For", "number of bytes written",
			"expecting", len(b),
			"got", n,
		)
		return
	}
	if err != nil {
		t.Error(
			"For", "simple write",
			"expecting", "nil error",
			"got", err,
		)
		return
	}

	b2 := make([]byte, len(b))
	n, err = pipe.Read(b2)
	if n != len(b) {
		t.Error(
			"For", "number of bytes read",
			"expecting", len(b),
			"got", n,
		)
		return
	}
	if err != nil {
		t.Error(
			"For", "simple read",
			"expecting", "nil error",
			"got", err,
		)
		return
	}
	if !bytes.Equal(b, b2) {
		t.Error(
			"For", "simple read",
			"expecting", b,
			"got", b2,
		)
	}

}

func TestReadBlock(t *testing.T) {
	pipe := NewStreamBufferedPipe()
	b := []byte{0x01, 0x02, 0x03}
	go func() {
		time.Sleep(100 * time.Millisecond)
		pipe.Write(b)
	}()
	b2 := make([]byte, len(b))
	n, err := pipe.Read(b2)
	if n != len(b) {
		t.Error(
			"For", "number of bytes read after block",
			"expecting", len(b),
			"got", n,
		)
		return
	}
	if err != nil {
		t.Error(
			"For", "blocked read",
			"expecting", "nil error",
			"got", err,
		)
		return
	}
	if !bytes.Equal(b, b2) {
		t.Error(
			"For", "blocked read",
			"expecting", b,
			"got", b2,
		)
		return
	}
}

func TestPartialRead(t *testing.T) {
	pipe := NewStreamBufferedPipe()
	b := []byte{0x01, 0x02, 0x03}
	pipe.Write(b)
	b1 := make([]byte, 1)
	n, err := pipe.Read(b1)
	if n != len(b1) {
		t.Error(
			"For", "number of bytes in partial read of 1",
			"expecting", len(b1),
			"got", n,
		)
		return
	}
	if err != nil {
		t.Error(
			"For", "partial read of 1",
			"expecting", "nil error",
			"got", err,
		)
		return
	}
	if b1[0] != b[0] {
		t.Error(
			"For", "partial read of 1",
			"expecting", b[0],
			"got", b1[0],
		)
	}
	b2 := make([]byte, 2)
	n, err = pipe.Read(b2)
	if n != len(b2) {
		t.Error(
			"For", "number of bytes in partial read of 2",
			"expecting", len(b2),
			"got", n,
		)
	}
	if err != nil {
		t.Error(
			"For", "partial read of 2",
			"expecting", "nil error",
			"got", err,
		)
		return
	}
	if !bytes.Equal(b[1:], b2) {
		t.Error(
			"For", "partial read of 2",
			"expecting", b[1:],
			"got", b2,
		)
		return
	}
}

func TestReadAfterClose(t *testing.T) {
	pipe := NewStreamBufferedPipe()
	b := []byte{0x01, 0x02, 0x03}
	pipe.Write(b)
	b2 := make([]byte, len(b))
	pipe.Close()
	n, err := pipe.Read(b2)
	if n != len(b) {
		t.Error(
			"For", "number of bytes read",
			"expecting", len(b),
			"got", n,
		)
	}
	if err != nil {
		t.Error(
			"For", "simple read",
			"expecting", "nil error",
			"got", err,
		)
		return
	}
	if !bytes.Equal(b, b2) {
		t.Error(
			"For", "simple read",
			"expecting", b,
			"got", b2,
		)
		return
	}
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
