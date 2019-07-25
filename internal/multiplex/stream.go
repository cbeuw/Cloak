package multiplex

import (
	"errors"
	"io"
	"log"
	"net"
	"time"

	//"log"
	"math"
	prand "math/rand"
	"sync"
	"sync/atomic"
)

var ErrBrokenStream = errors.New("broken stream")

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
	feederR     *io.PipeReader
	feederW     *io.PipeWriter

	// atomic
	nextSendSeq uint32

	writingM sync.RWMutex

	// close(die) is used to notify different goroutines that this stream is closing
	die        chan struct{}
	heliumMask sync.Once // my personal fav
}

func makeStream(id uint32, sesh *Session) *Stream {
	r, w := io.Pipe()
	stream := &Stream{
		id:          id,
		session:     sesh,
		die:         make(chan struct{}),
		sh:          []*frameNode{},
		newFrameCh:  make(chan *Frame, 1024),
		sortedBufCh: make(chan []byte, 1024),
		feederR:     r,
		feederW:     w,
	}
	go stream.recvNewFrame()
	go stream.feed()
	return stream
}

func (stream *Stream) feed() {
	for {
		select {
		case <-stream.die:
			return
		case data := <-stream.sortedBufCh:
			if len(data) == 0 {
				stream.passiveClose()
				return
			}
			_, err := stream.feederW.Write(data)
			if err != nil {
				log.Println(err)
			}
		}
	}
}

func (stream *Stream) Read(buf []byte) (n int, err error) {
	if len(buf) == 0 {
		select {
		case <-stream.die:
			return 0, ErrBrokenStream
		default:
			return 0, nil
		}
	}
	select {
	case <-stream.die:
		return 0, ErrBrokenStream
	default:
		return stream.feederR.Read(buf)
	}

}

func (stream *Stream) Write(in []byte) (n int, err error) {
	// RWMutex used here isn't really for RW.
	// we use it to exploit the fact that RLock doesn't create contention.
	// The use of RWMutex is so that the stream will not actively close
	// in the middle of the execution of Write. This may cause the closing frame
	// to be sent before the data frame and cause loss of packet.
	stream.writingM.RLock()
	select {
	case <-stream.die:
		stream.writingM.RUnlock()
		return 0, ErrBrokenStream
	default:
	}

	f := &Frame{
		StreamID: stream.id,
		Seq:      atomic.AddUint32(&stream.nextSendSeq, 1) - 1,
		Closing:  0,
		Payload:  in,
	}

	tlsRecord, err := stream.session.obfs(f)
	if err != nil {
		stream.writingM.RUnlock()
		return 0, err
	}
	n, err = stream.session.sb.send(tlsRecord)
	stream.writingM.RUnlock()

	return

}

// only close locally. Used when the stream close is notified by the remote
func (stream *Stream) passiveClose() {
	stream.heliumMask.Do(func() { close(stream.die) })
	stream.session.delStream(stream.id)
	//log.Printf("%v passive closing\n", stream.id)
}

// active close. Close locally and tell the remote that this stream is being closed
func (stream *Stream) Close() error {

	stream.writingM.Lock()
	select {
	case <-stream.die:
		stream.writingM.Unlock()
		return errors.New("Already Closed")
	default:
	}
	stream.heliumMask.Do(func() { close(stream.die) })

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
	tlsRecord, _ := stream.session.obfs(f)
	stream.session.sb.send(tlsRecord)

	stream.session.delStream(stream.id)
	//log.Printf("%v actively closed\n", stream.id)
	stream.writingM.Unlock()
	return nil
}

// Same as passiveClose() but no call to session.delStream.
// This is called in session.Close() to avoid mutex deadlock
// We don't notify the remote because session.Close() is always
// called when the session is passively closed
func (stream *Stream) closeNoDelMap() {
	stream.heliumMask.Do(func() { close(stream.die) })
}

// the following functions are purely for implementing net.Conn interface.
// they are not used
var errNotImplemented = errors.New("Not implemented")

func (stream *Stream) LocalAddr() net.Addr  { return stream.session.addrs.Load().([]net.Addr)[0] }
func (stream *Stream) RemoteAddr() net.Addr { return stream.session.addrs.Load().([]net.Addr)[1] }

// TODO: implement the following
func (stream *Stream) SetDeadline(t time.Time) error      { return errNotImplemented }
func (stream *Stream) SetReadDeadline(t time.Time) error  { return errNotImplemented }
func (stream *Stream) SetWriteDeadline(t time.Time) error { return errNotImplemented }
