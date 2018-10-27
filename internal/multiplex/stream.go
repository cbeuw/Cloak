package multiplex

import (
	"errors"
	"log"
	"sync"
	"sync/atomic"
)

var errBrokenStream = errors.New("broken stream")
var errRepeatStreamClosing = errors.New("trying to close a closed stream")

type Stream struct {
	id uint32

	session *Session

	// Explanations of the following 4 fields can be found in frameSorter.go
	nextRecvSeq uint32
	rev         int
	sh          sorterHeap
	wrapMode    bool

	// New frames are received through newFrameCh by frameSorter
	newFrameCh chan *Frame
	// sortedBufCh are order-sorted data ready to be read raw
	sortedBufCh chan []byte

	nextSendSeq uint32

	closingM sync.Mutex
	// close(die) is used to notify different goroutines that this stream is closing
	die chan struct{}
	// to prevent closing a closed channel
	closing bool
}

func makeStream(id uint32, sesh *Session) *Stream {
	stream := &Stream{
		id:          id,
		session:     sesh,
		die:         make(chan struct{}),
		sh:          []*frameNode{},
		newFrameCh:  make(chan *Frame, 1024),
		sortedBufCh: make(chan []byte, 4096),
	}
	go stream.recvNewFrame()
	return stream
}

func (stream *Stream) Read(buf []byte) (n int, err error) {
	if len(buf) == 0 {
		select {
		case <-stream.die:
			log.Printf("Stream %v dying\n", stream.id)
			return 0, errBrokenStream
		default:
			return 0, nil
		}
	}
	select {
	case <-stream.die:
		log.Printf("Stream %v dying\n", stream.id)
		return 0, errBrokenStream
	case data := <-stream.sortedBufCh:
		if len(buf) < len(data) {
			log.Println(len(data))
			return 0, errors.New("buf too small")
		}
		copy(buf, data)
		return len(data), nil
	}

}

func (stream *Stream) Write(in []byte) (n int, err error) {
	select {
	case <-stream.die:
		log.Printf("Stream %v dying\n", stream.id)
		return 0, errBrokenStream
	default:
	}

	var closingID uint32

	select {
	case closingID = <-stream.session.closeQCh:
	default:
	}

	f := &Frame{
		StreamID:        stream.id,
		Seq:             stream.nextSendSeq,
		ClosingStreamID: closingID,
		Payload:         in,
	}

	atomic.AddUint32(&stream.nextSendSeq, 1)

	tlsRecord := stream.session.obfs(f)
	stream.session.sb.dispatCh <- tlsRecord

	return len(in), nil

}

func (stream *Stream) Close() error {
	log.Printf("ID: %v closing\n", stream.id)

	// Lock here because closing a closed channel causes panic
	stream.closingM.Lock()
	defer stream.closingM.Unlock()
	if stream.closing {
		return errRepeatStreamClosing
	}
	stream.closing = true
	close(stream.die)
	stream.session.delStream(stream.id)
	stream.session.closeQCh <- stream.id
	return nil
}

// Same as Close() but no call to session.delStream.
// This is called in session.Close() to avoid mutex deadlock
func (stream *Stream) closeNoDelMap() error {
	log.Printf("ID: %v closing\n", stream.id)

	// Lock here because closing a closed channel causes panic
	stream.closingM.Lock()
	defer stream.closingM.Unlock()
	if stream.closing {
		return errRepeatStreamClosing
	}
	stream.closing = true
	close(stream.die)
	stream.session.closeQCh <- stream.id
	return nil
}
