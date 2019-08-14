package multiplex

import (
	"bytes"
	"testing"
	"time"
)

func TestDatagramBuffer_RW(t *testing.T) {
	pipe := NewDatagramBuffer()
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
	if pipe.Len() != 0 {
		t.Error("buf len is not 0 after finished reading")
		return
	}

}

func TestDatagramBuffer_BlockingRead(t *testing.T) {
	pipe := NewDatagramBuffer()
	b := []byte{0x01, 0x02, 0x03}
	go func() {
		time.Sleep(10 * time.Millisecond)
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

func TestDatagramBuffer_CloseThenRead(t *testing.T) {
	pipe := NewDatagramBuffer()
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
