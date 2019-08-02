package multiplex

import (
	"errors"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
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

	sortedBuf *bufferedPipe

	// atomic
	nextSendSeq uint32

	writingM sync.RWMutex

	// close(die) is used to notify different goroutines that this stream is closing
	closed uint32
}

func makeStream(id uint32, sesh *Session) *Stream {
	stream := &Stream{
		id:         id,
		session:    sesh,
		sh:         []*frameNode{},
		newFrameCh: make(chan *Frame, 1024),
		sortedBuf:  NewBufferedPipe(),
	}
	go stream.recvNewFrame()
	log.Tracef("stream %v opened", id)
	return stream
}

func (s *Stream) isClosed() bool { return atomic.LoadUint32(&s.closed) == 1 }

func (s *Stream) Read(buf []byte) (n int, err error) {
	if len(buf) == 0 {
		if s.isClosed() {
			return 0, ErrBrokenStream
		} else {
			return 0, nil
		}
	}
	if s.isClosed() {
		if s.sortedBuf.Len() == 0 {
			return 0, ErrBrokenStream
		} else {
			return s.sortedBuf.Read(buf)
		}
	} else {
		return s.sortedBuf.Read(buf)
	}

}

func (s *Stream) Write(in []byte) (n int, err error) {
	// RWMutex used here isn't really for RW.
	// we use it to exploit the fact that RLock doesn't create contention.
	// The use of RWMutex is so that the stream will not actively close
	// in the middle of the execution of Write. This may cause the closing frame
	// to be sent before the data frame and cause loss of packet.
	s.writingM.RLock()
	defer s.writingM.RUnlock()
	if s.isClosed() {
		return 0, ErrBrokenStream
	}

	f := &Frame{
		StreamID: s.id,
		Seq:      atomic.AddUint32(&s.nextSendSeq, 1) - 1,
		Closing:  0,
		Payload:  in,
	}

	tlsRecord, err := s.session.Obfs(f)
	if err != nil {
		return 0, err
	}
	n, err = s.session.sb.send(tlsRecord)
	return

}

// the necessary steps to mark the stream as closed and to release resources
func (s *Stream) _close() {
	atomic.StoreUint32(&s.closed, 1)
	s.newFrameCh <- nil // this will trigger frameSorter to return
	s.sortedBuf.Close()
}

// only close locally. Used when the stream close is notified by the remote
func (s *Stream) passiveClose() {
	s._close()
	s.session.delStream(s.id)
	log.WithField("streamId", s.id).Trace("stream passively closed")
}

// active close. Close locally and tell the remote that this stream is being closed
func (s *Stream) Close() error {

	s.writingM.Lock()
	defer s.writingM.Unlock()
	if s.isClosed() {
		return errors.New("Already Closed")
	}

	// Notify remote that this stream is closed
	prand.Seed(int64(s.id))
	padLen := int(math.Floor(prand.Float64()*200 + 300))
	pad := make([]byte, padLen)
	prand.Read(pad)
	f := &Frame{
		StreamID: s.id,
		Seq:      atomic.AddUint32(&s.nextSendSeq, 1) - 1,
		Closing:  1,
		Payload:  pad,
	}
	tlsRecord, _ := s.session.Obfs(f)
	s.session.sb.send(tlsRecord)

	s._close()
	s.session.delStream(s.id)
	log.WithField("streamId", s.id).Trace("stream actively closed")
	return nil
}

// Same as passiveClose() but no call to session.delStream.
// This is called in session.Close() to avoid mutex deadlock
// We don't notify the remote because session.Close() is always
// called when the session is passively closed
func (s *Stream) closeNoDelMap() {
	log.WithField("streamId", s.id).Trace("stream closed by session")
	s._close()
}

// the following functions are purely for implementing net.Conn interface.
// they are not used
var errNotImplemented = errors.New("Not implemented")

func (s *Stream) LocalAddr() net.Addr  { return s.session.addrs.Load().([]net.Addr)[0] }
func (s *Stream) RemoteAddr() net.Addr { return s.session.addrs.Load().([]net.Addr)[1] }

// TODO: implement the following
func (s *Stream) SetDeadline(t time.Time) error      { return errNotImplemented }
func (s *Stream) SetReadDeadline(t time.Time) error  { return errNotImplemented }
func (s *Stream) SetWriteDeadline(t time.Time) error { return errNotImplemented }
