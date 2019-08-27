package multiplex

type Frame struct {
	StreamID uint32
	Seq      uint64
	Closing  uint8
	Payload  []byte
}
