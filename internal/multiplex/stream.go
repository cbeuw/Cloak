package multiplex

import (
	"errors"
	"io"
	"sync"
)

const (
	readBuffer = 10240
)

type Stream struct {
	id uint32

	session *Session

	// Copied from smux
	dieM sync.Mutex
	die  chan struct{}

	// Explanations of the following 4 fields can be found in frameSorter.go
	nextRecvSeq uint32
	rev         int
	sh          sorterHeap
	wrapMode    bool

	sortedBufCh chan []byte

	nextSendSeqM sync.Mutex
	nextSendSeq  uint32
}

func makeStream(id uint32, sesh *Session) *Stream {
	stream := &Stream{
		id:      id,
		session: sesh,
	}
	return stream
}

func (stream *Stream) Read(buf []byte) (n int, err error) {
	if len(buf) == 0 {
		select {
		case <-stream.die:
			return 0, errors.New(errBrokenPipe)
		case data := <-stream.sortedBufCh:
			if len(data) > 0 {
				copy(buf, data)
				return len(data), nil
			} else {
				// TODO: close stream here or not?
				return 0, io.EOF
			}
		}
	}
	return 0, errors.New(errBrokenPipe)

}

func (stream *Stream) Write(in []byte) (n int, err error) {
	select {
	case <-stream.die:
		return 0, errors.New(errBrokenPipe)
	default:
	}

	var closingID uint32

	select {
	case closingID = <-stream.session.closeQCh:
	default:
	}

	f := &Frame{
		StreamID:       stream.id,
		Seq:            stream.nextSendSeq,
		ClosedStreamID: closingID,
	}
	copy(f.Payload, in)

	stream.nextSendSeqM.Lock()
	stream.nextSendSeq += 1
	stream.nextSendSeqM.Unlock()

	tlsRecord := stream.session.obfs(f)
	stream.session.sb.dispatCh <- tlsRecord

	return len(in), nil

}

func (stream *Stream) Close() error {
	stream.session.delStream(stream.id)
	close(stream.die)
	close(stream.sortedBufCh)
	stream.session.closeQCh <- stream.id
	return nil
}
