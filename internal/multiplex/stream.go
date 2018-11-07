package multiplex

import (
	"errors"
	"log"
	"math"
	prand "math/rand"
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

	// atomic
	nextSendSeq uint32

	closingM sync.RWMutex
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
		sortedBufCh: make(chan []byte, 1024),
	}
	go stream.recvNewFrame()
	return stream
}

func (stream *Stream) Read(buf []byte) (n int, err error) {
	if len(buf) == 0 {
		select {
		case <-stream.die:
			return 0, errBrokenStream
		default:
			return 0, nil
		}
	}
	select {
	case <-stream.die:
		return 0, errBrokenStream
	case data := <-stream.sortedBufCh:
		if len(data) == 0 {
			stream.passiveClose()
			return 0, errBrokenStream
		}
		if len(buf) < len(data) {
			log.Println(len(data))
			return 0, errors.New("buf too small")
		}
		copy(buf, data)
		return len(data), nil
	}

}

func (stream *Stream) Write(in []byte) (n int, err error) {
	// RWMutex used here isn't really for RW.
	// we use it to exploit the fact that RLock doesn't create contention.
	// The use of RWMutex is so that the stream will not actively close
	// in the middle of the execution of Write. This may cause the closing frame
	// to be sent before the data frame and cause loss of packet.
	stream.closingM.RLock()
	defer stream.closingM.RUnlock()
	select {
	case <-stream.die:
		return 0, errBrokenStream
	default:
	}

	f := &Frame{
		StreamID: stream.id,
		Seq:      atomic.AddUint32(&stream.nextSendSeq, 1) - 1,
		Closing:  0,
		Payload:  in,
	}

	tlsRecord := stream.session.obfs(f)
	n, err = stream.session.sb.send(tlsRecord)

	return

}

func (stream *Stream) shutdown() error {
	// Lock here because closing a closed channel causes panic
	stream.closingM.Lock()
	defer stream.closingM.Unlock()
	if stream.closing {
		return errRepeatStreamClosing
	}
	stream.closing = true
	close(stream.die)
	return nil
}

// only close locally. Used when the stream close is notified by the remote
func (stream *Stream) passiveClose() error {
	err := stream.shutdown()
	if err != nil {
		return err
	}
	stream.session.delStream(stream.id)
	log.Printf("%v passive closing\n", stream.id)
	return nil
}

// active close. Close locally and tell the remote that this stream is being closed
func (stream *Stream) Close() error {

	err := stream.shutdown()
	if err != nil {
		return err
	}

	// Notify remote that this stream is closed
	prand.Seed(int64(stream.id))
	padLen := int(math.Floor(prand.Float64()*200 + 300))
	pad := make([]byte, padLen)
	prand.Read(pad)
	f := &Frame{
		StreamID: stream.id,
		Seq:      atomic.AddUint32(&stream.nextSendSeq, 1) - 1,
		Closing:  1,
		Payload:  pad,
	}
	tlsRecord := stream.session.obfs(f)
	stream.session.sb.send(tlsRecord)

	stream.session.delStream(stream.id)
	log.Printf("%v actively closed\n", stream.id)
	return nil
}

// Same as Close() but no call to session.delStream.
// This is called in session.Close() to avoid mutex deadlock
func (stream *Stream) closeNoDelMap() error {
	return stream.shutdown()
}
