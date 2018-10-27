package multiplex

import ()

type Frame struct {
	StreamID uint32
	Seq      uint32
	Closing  uint32
	Payload  []byte
}
