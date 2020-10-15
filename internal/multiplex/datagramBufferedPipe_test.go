package multiplex

import (
	"bytes"
	"testing"
	"time"
)

func TestDatagramBuffer_RW(t *testing.T) {
	b := []byte{0x01, 0x02, 0x03}
	t.Run("simple write", func(t *testing.T) {
		pipe := NewDatagramBufferedPipe()
		_, err := pipe.Write(Frame{Payload: b})
		if err != nil {
			t.Error(
				"expecting", "nil error",
				"got", err,
			)
			return
		}
	})

	t.Run("simple read", func(t *testing.T) {
		pipe := NewDatagramBufferedPipe()
		_, _ = pipe.Write(Frame{Payload: b})
		b2 := make([]byte, len(b))
		n, err := pipe.Read(b2)
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
				"expecting", "nil error",
				"got", err,
			)
			return
		}
		if !bytes.Equal(b, b2) {
			t.Error(
				"expecting", b,
				"got", b2,
			)
		}
		if pipe.buf.Len() != 0 {
			t.Error("buf len is not 0 after finished reading")
			return
		}

	})

	t.Run("writing closing frame", func(t *testing.T) {
		pipe := NewDatagramBufferedPipe()
		toBeClosed, err := pipe.Write(Frame{Closing: C_STREAM})
		if !toBeClosed {
			t.Error("should be to be closed")
		}
		if err != nil {
			t.Error(
				"expecting", "nil error",
				"got", err,
			)
			return
		}
		if !pipe.closed {
			t.Error("expecting closed pipe, not closed")
		}
	})
}

func TestDatagramBuffer_BlockingRead(t *testing.T) {
	pipe := NewDatagramBufferedPipe()
	b := []byte{0x01, 0x02, 0x03}
	go func() {
		time.Sleep(100 * time.Millisecond)
		pipe.Write(Frame{Payload: b})
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
	pipe := NewDatagramBufferedPipe()
	b := []byte{0x01, 0x02, 0x03}
	pipe.Write(Frame{Payload: b})
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
