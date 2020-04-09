package multiplex

import (
	"io"
	"time"
)

type recvBuffer interface {
	// Read calls' err must be nil | io.EOF | io.ErrShortBuffer
	io.ReadCloser
	Write(Frame) (toBeClosed bool, err error)
	SetReadDeadline(time time.Time)
}
