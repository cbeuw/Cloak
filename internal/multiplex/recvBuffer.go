package multiplex

import (
	"io"
	"time"
)

type recvBuffer interface {
	// Read calls' err must be nil | io.EOF | io.ErrShortBuffer
	io.ReadCloser
	io.WriterTo
	Write(Frame) (toBeClosed bool, err error)
	SetReadDeadline(time time.Time)
	SetWriteToTimeout(d time.Duration)
}
