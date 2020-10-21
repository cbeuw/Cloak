package multiplex

const (
	closingNothing = iota
	closingStream
	closingSession
)

type Frame struct {
	StreamID uint32
	Seq      uint64
	Closing  uint8
	Payload  []byte
}
