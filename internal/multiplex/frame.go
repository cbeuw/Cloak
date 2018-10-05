package multiplex

import ()

type Frame struct {
	StreamID       uint32
	Seq            uint32
	ClosedStreamID uint32
	Payload        []byte
}
