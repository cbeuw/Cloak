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
	io.WriterTo
	Write(Frame) (toBeClosed bool, err error)
	SetReadDeadline(time time.Time)
	// SetWriteToTimeout sets the duration a recvBuffer waits in a WriteTo call when nothing
	// has been written for a while. After that duration it should return ErrTimeout
	SetWriteToTimeout(d time.Duration)
}
