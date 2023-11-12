package multiplex

import (
	"errors"
	"io"
	"time"
)

var ErrTimeout = errors.New("deadline exceeded")

type recvBuffer interface {
	// Read calls' err must be nil | io.EOF | io.ErrShortBuffer
	// Read should NOT return error on a closed streamBuffer with a non-empty buffer.
	// Instead, it should behave as if it hasn't been closed. Closure is only relevant
	// when the buffer is empty.
	io.ReadCloser
	Write(*Frame) (toBeClosed bool, err error)
	SetReadDeadline(time time.Time)
}

// size we want the amount of unread data in buffer to grow before recvBuffer.Write blocks.
// If the buffer grows larger than what the system's memory can offer at the time of recvBuffer.Write,
// a panic will happen.
const recvBufferSizeLimit = 1<<31 - 1
