package multiplex

import (
	"errors"
	"io"
	"net"
	"time"

	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
)

var ErrBrokenStream = errors.New("broken stream")

// Stream implements net.Conn. It represents an optionally-ordered, full-duplex, self-contained connection.
// If the session it belongs to runs in ordered mode, it provides ordering guarantee regardless of the underlying
// connection used.
// If the underlying connections the session uses are reliable, Stream is reliable. If they are not, Stream does not
// guarantee reliability.
type Stream struct {
	id uint32

	session *Session

	// a buffer (implemented as an asynchronous buffered pipe) to put data we've received from recvFrame but hasn't
	// been read by the consumer through Read or WriteTo.
	recvBuf recvBuffer

	writingM     sync.Mutex
	writingFrame Frame // we do the allocation here to save repeated allocations in Write and ReadFrom

	// atomic
	closed uint32

	// When we want order guarantee (i.e. session.Unordered is false),
	// we assign each stream a fixed underlying connection.
	// If the underlying connections the session uses provide ordering guarantee (most likely TCP),
	// recvBuffer (implemented by streamBuffer under ordered mode) will not receive out-of-order packets
	// so it won't have to use its priority queue to sort it.
	// This is not used in unordered connection mode
	assignedConn net.Conn

	readFromTimeout time.Duration
}

func makeStream(sesh *Session, id uint32) *Stream {
	stream := &Stream{
		id:      id,
		session: sesh,
		writingFrame: Frame{
			StreamID: id,
			Seq:      0,
			Closing:  closingNothing,
		},
	}

	if sesh.Unordered {
		stream.recvBuf = NewDatagramBufferedPipe()
	} else {
		stream.recvBuf = NewStreamBuffer()
	}

	return stream
}

func (s *Stream) isClosed() bool { return atomic.LoadUint32(&s.closed) == 1 }

// receive a readily deobfuscated Frame so its payload can later be Read
func (s *Stream) recvFrame(frame *Frame) error {
	toBeClosed, err := s.recvBuf.Write(frame)
	if toBeClosed {
		err = s.passiveClose()
		if errors.Is(err, errRepeatStreamClosing) {
			log.Debug(err)
			return nil
		}
		return err
	}
	return err
}

// Read implements io.Read
func (s *Stream) Read(buf []byte) (n int, err error) {
	//log.Tracef("attempting to read from stream %v", s.id)
	if len(buf) == 0 {
		return 0, nil
	}

	n, err = s.recvBuf.Read(buf)
	log.Tracef("%v read from stream %v with err %v", n, s.id, err)
	if err == io.EOF {
		return n, ErrBrokenStream
	}
	return
}

func (s *Stream) obfuscateAndSend(buf []byte, payloadOffsetInBuf int) error {
	cipherTextLen, err := s.session.obfuscate(&s.writingFrame, buf, payloadOffsetInBuf)
	s.writingFrame.Seq++
	if err != nil {
		return err
	}

	_, err = s.session.sb.send(buf[:cipherTextLen], &s.assignedConn)
	if err != nil {
		if err == errBrokenSwitchboard {
			s.session.SetTerminalMsg(err.Error())
			s.session.passiveClose()
		}
		return err
	}
	return nil
}

// Write implements io.Write
func (s *Stream) Write(in []byte) (n int, err error) {
	s.writingM.Lock()
	defer s.writingM.Unlock()
	if s.isClosed() {
		return 0, ErrBrokenStream
	}

	for n < len(in) {
		var framePayload []byte
		if len(in)-n <= s.session.maxStreamUnitWrite {
			// if we can fit remaining data of in into one frame
			framePayload = in[n:]
		} else {
			// if we have to split
			if s.session.Unordered {
				// but we are not allowed to
				err = io.ErrShortBuffer
				return
			}
			framePayload = in[n : s.session.maxStreamUnitWrite+n]
		}
		s.writingFrame.Payload = framePayload
		buf := s.session.streamObfsBufPool.Get().(*[]byte)
		err = s.obfuscateAndSend(*buf, 0)
		s.session.streamObfsBufPool.Put(buf)
		if err != nil {
			return
		}
		n += len(framePayload)
	}
	return
}

// ReadFrom continuously read data from r and send it off, until either r returns error or nothing has been read
// for readFromTimeout amount of time
func (s *Stream) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		if s.readFromTimeout != 0 {
			if rder, ok := r.(net.Conn); !ok {
				log.Warn("ReadFrom timeout is set but reader doesn't implement SetReadDeadline")
			} else {
				rder.SetReadDeadline(time.Now().Add(s.readFromTimeout))
			}
		}
		buf := s.session.streamObfsBufPool.Get().(*[]byte)
		read, er := r.Read((*buf)[frameHeaderLength : frameHeaderLength+s.session.maxStreamUnitWrite])
		if er != nil {
			return n, er
		}

		// the above read may have been unblocked by another goroutine calling stream.Close(), so we need
		// to check that here
		if s.isClosed() {
			return n, ErrBrokenStream
		}

		s.writingM.Lock()
		s.writingFrame.Payload = (*buf)[frameHeaderLength : frameHeaderLength+read]
		err = s.obfuscateAndSend(*buf, frameHeaderLength)
		s.writingM.Unlock()
		s.session.streamObfsBufPool.Put(buf)

		if err != nil {
			return
		}
		n += int64(read)
	}
}

func (s *Stream) passiveClose() error {
	return s.session.closeStream(s, false)
}

// active close. Close locally and tell the remote that this stream is being closed
func (s *Stream) Close() error {
	s.writingM.Lock()
	defer s.writingM.Unlock()

	return s.session.closeStream(s, true)
}

func (s *Stream) LocalAddr() net.Addr  { return s.session.addrs.Load().([]net.Addr)[0] }
func (s *Stream) RemoteAddr() net.Addr { return s.session.addrs.Load().([]net.Addr)[1] }

func (s *Stream) SetReadDeadline(t time.Time) error  { s.recvBuf.SetReadDeadline(t); return nil }
func (s *Stream) SetReadFromTimeout(d time.Duration) { s.readFromTimeout = d }

var errNotImplemented = errors.New("Not implemented")

// the following functions are purely for implementing net.Conn interface.
// they are not used
// TODO: implement the following
func (s *Stream) SetDeadline(t time.Time) error      { return errNotImplemented }
func (s *Stream) SetWriteDeadline(t time.Time) error { return errNotImplemented }
