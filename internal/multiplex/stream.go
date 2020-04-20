package multiplex

import (
	"errors"
	"io"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	"sync"
	"sync/atomic"
)

var ErrBrokenStream = errors.New("broken stream")

type Stream struct {
	id uint32

	session *Session

	recvBuf recvBuffer

	nextSendSeq uint64

	writingM sync.Mutex

	// atomic
	closed uint32

	// only alloc when writing to the stream
	allocIdempot sync.Once
	obfsBuf      []byte

	// we assign each stream a fixed underlying TCP connection to utilise order guarantee provided by TCP itself
	// so that frameSorter should have few to none ooo frames to deal with
	// overall the streams in a session should be uniformly distributed across all connections
	// This is not used in unordered connection mode
	assignedConnId uint32

	rfTimeout time.Duration
}

func makeStream(sesh *Session, id uint32) *Stream {
	var recvBuf recvBuffer
	if sesh.Unordered {
		recvBuf = NewDatagramBuffer()
	} else {
		recvBuf = NewStreamBuffer()
	}

	stream := &Stream{
		id:      id,
		session: sesh,
		recvBuf: recvBuf,
	}

	return stream
}

func (s *Stream) isClosed() bool { return atomic.LoadUint32(&s.closed) == 1 }

func (s *Stream) writeFrame(frame Frame) error {
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

func (s *Stream) WriteTo(w io.Writer) (int64, error) {
	// will keep writing until the underlying buffer is closed
	n, err := s.recvBuf.WriteTo(w)
	log.Tracef("%v read from stream %v with err %v", n, s.id, err)
	if err == io.EOF {
		return n, ErrBrokenStream
	}
	return n, nil
}

func (s *Stream) sendFrame(f *Frame, framePayloadOffset int) error {
	var cipherTextLen int
	cipherTextLen, err := s.session.Obfs(f, s.obfsBuf, framePayloadOffset)
	if err != nil {
		return err
	}

	_, err = s.session.sb.send(s.obfsBuf[:cipherTextLen], &s.assignedConnId)
	log.Tracef("%v sent to remote through stream %v with err %v. seq: %v", len(f.Payload), s.id, err, f.Seq)
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

	if s.obfsBuf == nil {
		s.obfsBuf = make([]byte, s.session.SendBufferSize)
	}
	for n < len(in) {
		var framePayload []byte
		if len(in)-n <= s.session.maxStreamUnitWrite {
			framePayload = in[n:]
		} else {
			if s.session.Unordered { // no splitting
				err = io.ErrShortBuffer
				return
			}
			framePayload = in[n : s.session.maxStreamUnitWrite+n]
		}
		f := &Frame{
			StreamID: s.id,
			Seq:      s.nextSendSeq,
			Closing:  C_NOOP,
			Payload:  framePayload,
		}
		s.nextSendSeq++
		err = s.sendFrame(f, 0)
		if err != nil {
			return
		}
		n += len(framePayload)
	}
	return
}

func (s *Stream) ReadFrom(r io.Reader) (n int64, err error) {
	if s.obfsBuf == nil {
		s.obfsBuf = make([]byte, s.session.SendBufferSize)
	}
	for {
		if s.rfTimeout != 0 {
			if rder, ok := r.(net.Conn); !ok {
				log.Warn("ReadFrom timeout is set but reader doesn't implement SetReadDeadline")
			} else {
				rder.SetReadDeadline(time.Now().Add(s.rfTimeout))
			}
		}
		read, er := r.Read(s.obfsBuf[HEADER_LEN : HEADER_LEN+s.session.maxStreamUnitWrite])
		if er != nil {
			return n, er
		}
		if s.isClosed() {
			return n, ErrBrokenStream
		}

		s.writingM.Lock()
		f := &Frame{
			StreamID: s.id,
			Seq:      s.nextSendSeq,
			Closing:  C_NOOP,
			Payload:  s.obfsBuf[HEADER_LEN : HEADER_LEN+read],
		}
		s.nextSendSeq++
		err = s.sendFrame(f, HEADER_LEN)
		s.writingM.Unlock()

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

// the following functions are purely for implementing net.Conn interface.
// they are not used
var errNotImplemented = errors.New("Not implemented")

func (s *Stream) LocalAddr() net.Addr  { return s.session.addrs.Load().([]net.Addr)[0] }
func (s *Stream) RemoteAddr() net.Addr { return s.session.addrs.Load().([]net.Addr)[1] }

// TODO: implement the following
func (s *Stream) SetDeadline(t time.Time) error      { return errNotImplemented }
func (s *Stream) SetWriteToTimeout(d time.Duration)  { s.recvBuf.SetWriteToTimeout(d) }
func (s *Stream) SetReadDeadline(t time.Time) error  { s.recvBuf.SetReadDeadline(t); return nil }
func (s *Stream) SetReadFromTimeout(d time.Duration) { s.rfTimeout = d }
func (s *Stream) SetWriteDeadline(t time.Time) error { return errNotImplemented }
