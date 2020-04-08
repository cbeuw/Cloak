package multiplex

import "io"

type recvBuffer interface {
	// Read calls' err must be nil | io.EOF | io.ErrShortBuffer
	io.ReadCloser
	Write(Frame) (toBeClosed bool, err error)
}
