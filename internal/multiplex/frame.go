package multiplex

const (
	C_NOOP = iota
	C_STREAM
	C_SESSION
)

type Frame struct {
	StreamID uint32
	Seq      uint64
	Closing  uint8
	Payload  []byte
}
