package multiplex

import ()

type Frame struct {
	StreamID        uint32
	Seq             uint32
	ClosingStreamID uint32
	Payload         []byte
}
