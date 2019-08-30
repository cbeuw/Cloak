package multiplex

import "io"

type recvBuffer interface {
	io.ReadCloser
	Write(Frame) error
}
