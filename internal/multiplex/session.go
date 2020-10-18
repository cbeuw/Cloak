package multiplex

import (
	"errors"
	"fmt"
	"github.com/cbeuw/Cloak/internal/common"
	"net"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	acceptBacklog = 1024
	// TODO: will this be a signature?
	defaultSendRecvBufSize   = 20480
	defaultInactivityTimeout = 30 * time.Second
)

var ErrBrokenSession = errors.New("broken session")
var errRepeatSessionClosing = errors.New("trying to close a closed session")
var errRepeatStreamClosing = errors.New("trying to close a closed stream")
var errNoMultiplex = errors.New("a singleplexing session can have only one stream")

type switchboardStrategy int

type SessionConfig struct {
	Obfuscator

	Valve

	Unordered bool

	Singleplex bool

	// maximum size of an obfuscated frame, including headers and overhead
	MsgOnWireSizeLimit int

	// StreamSendBufferSize sets the buffer size used to send data from a Stream (Stream.obfsBuf)
	StreamSendBufferSize int
	// ConnReceiveBufferSize sets the buffer size used to receive data from an underlying Conn (allocated in
	// switchboard.deplex)
	ConnReceiveBufferSize int

	// InactivityTimeout sets the duration a Session waits while it has no active streams before it closes itself
	InactivityTimeout time.Duration
}

type Session struct {
	id uint32

	SessionConfig

	// atomic
	nextStreamID uint32

	// atomic
	activeStreamCount uint32
	streams           sync.Map

	// Switchboard manages all connections to remote
	sb *switchboard

	// Used for LocalAddr() and RemoteAddr() etc.
	addrs atomic.Value

	// For accepting new streams
	acceptCh chan *Stream

	closed uint32

	terminalMsg atomic.Value

	// the max size passed to Write calls before it splits it into multiple frames
	// i.e. the max size a piece of data can fit into a Frame.Payload
	maxStreamUnitWrite int
}

func MakeSession(id uint32, config SessionConfig) *Session {
	sesh := &Session{
		id:            id,
		SessionConfig: config,
		nextStreamID:  1,
		acceptCh:      make(chan *Stream, acceptBacklog),
	}
	sesh.addrs.Store([]net.Addr{nil, nil})

	if config.Valve == nil {
		sesh.Valve = UNLIMITED_VALVE
	}
	if config.StreamSendBufferSize <= 0 {
		sesh.StreamSendBufferSize = defaultSendRecvBufSize
	}
	if config.ConnReceiveBufferSize <= 0 {
		sesh.ConnReceiveBufferSize = defaultSendRecvBufSize
	}
	if config.MsgOnWireSizeLimit <= 0 {
		sesh.MsgOnWireSizeLimit = defaultSendRecvBufSize - 1024
	}
	if config.InactivityTimeout == 0 {
		sesh.InactivityTimeout = defaultInactivityTimeout
	}
	// todo: validation. this must be smaller than StreamSendBufferSize
	sesh.maxStreamUnitWrite = sesh.MsgOnWireSizeLimit - HEADER_LEN - sesh.Obfuscator.maxOverhead

	sesh.sb = makeSwitchboard(sesh)
	go sesh.timeoutAfter(sesh.InactivityTimeout)
	return sesh
}

func (sesh *Session) streamCountIncr() uint32 {
	return atomic.AddUint32(&sesh.activeStreamCount, 1)
}
func (sesh *Session) streamCountDecr() uint32 {
	return atomic.AddUint32(&sesh.activeStreamCount, ^uint32(0))
}
func (sesh *Session) streamCount() uint32 {
	return atomic.LoadUint32(&sesh.activeStreamCount)
}

func (sesh *Session) AddConnection(conn net.Conn) {
	sesh.sb.addConn(conn)
	addrs := []net.Addr{conn.LocalAddr(), conn.RemoteAddr()}
	sesh.addrs.Store(addrs)
}

func (sesh *Session) OpenStream() (*Stream, error) {
	if sesh.IsClosed() {
		return nil, ErrBrokenSession
	}
	id := atomic.AddUint32(&sesh.nextStreamID, 1) - 1
	// Because atomic.AddUint32 returns the value after incrementation
	if sesh.Singleplex && id > 1 {
		// if there are more than one streams, which shouldn't happen if we are
		// singleplexing
		return nil, errNoMultiplex
	}
	stream := makeStream(sesh, id)
	sesh.streams.Store(id, stream)
	sesh.streamCountIncr()
	log.Tracef("stream %v of session %v opened", id, sesh.id)
	return stream, nil
}

func (sesh *Session) Accept() (net.Conn, error) {
	if sesh.IsClosed() {
		return nil, ErrBrokenSession
	}
	stream := <-sesh.acceptCh
	if stream == nil {
		return nil, ErrBrokenSession
	}
	log.Tracef("stream %v of session %v accepted", stream.id, sesh.id)
	return stream, nil
}

func (sesh *Session) closeStream(s *Stream, active bool) error {
	if atomic.SwapUint32(&s.closed, 1) == 1 {
		return fmt.Errorf("closing stream %v: %w", s.id, errRepeatStreamClosing)
	}
	_ = s.recvBuf.Close() // recvBuf.Close should not return error

	if active {
		// Notify remote that this stream is closed
		padding := genRandomPadding()
		f := &Frame{
			StreamID: s.id,
			Seq:      s.nextSendSeq,
			Closing:  C_STREAM,
			Payload:  padding,
		}
		s.nextSendSeq++

		obfsBuf := make([]byte, len(padding)+HEADER_LEN+sesh.Obfuscator.maxOverhead)
		i, err := sesh.Obfs(f, obfsBuf, 0)
		if err != nil {
			return err
		}
		_, err = sesh.sb.send(obfsBuf[:i], &s.assignedConnId)
		if err != nil {
			return err
		}
		log.Tracef("stream %v actively closed. seq %v", s.id, f.Seq)
	} else {
		log.Tracef("stream %v passively closed", s.id)
	}

	// id may or may not exist as this is user input, if we use Delete(s.id) here it will panic
	sesh.streams.Store(s.id, nil)
	if sesh.streamCountDecr() == 0 {
		if sesh.Singleplex {
			return sesh.Close()
		} else {
			log.Debugf("session %v has no active stream left", sesh.id)
			go sesh.timeoutAfter(sesh.InactivityTimeout)
		}
	}
	return nil
}

// recvDataFromRemote deobfuscate the frame and read the Closing field. If it is a closing frame, it writes the frame
// to the stream buffer, otherwise it fetches the desired stream instance, or creates and stores one if it's a new
// stream and then writes to the stream buffer
func (sesh *Session) recvDataFromRemote(data []byte) error {
	frame, err := sesh.Deobfs(data)
	if err != nil {
		return fmt.Errorf("Failed to decrypt a frame for session %v: %v", sesh.id, err)
	}

	if frame.Closing == C_SESSION {
		sesh.SetTerminalMsg("Received a closing notification frame")
		return sesh.passiveClose()
	}

	newStream := makeStream(sesh, frame.StreamID)
	existingStreamI, existing := sesh.streams.LoadOrStore(frame.StreamID, newStream)
	if existing {
		if existingStreamI == nil {
			// this is when the stream existed before but has since been closed. We do nothing
			return nil
		}
		return existingStreamI.(*Stream).recvFrame(*frame)
	} else {
		// new stream
		sesh.streamCountIncr()
		sesh.acceptCh <- newStream
		return newStream.recvFrame(*frame)
	}
}

func (sesh *Session) SetTerminalMsg(msg string) {
	sesh.terminalMsg.Store(msg)
}

func (sesh *Session) TerminalMsg() string {
	msg := sesh.terminalMsg.Load()
	if msg != nil {
		return msg.(string)
	} else {
		return ""
	}
}

func (sesh *Session) passiveClose() error {
	log.Debugf("attempting to passively close session %v", sesh.id)
	if atomic.SwapUint32(&sesh.closed, 1) == 1 {
		log.Debugf("session %v has already been closed", sesh.id)
		return errRepeatSessionClosing
	}
	sesh.acceptCh <- nil

	sesh.streams.Range(func(key, streamI interface{}) bool {
		if streamI == nil {
			return true
		}
		stream := streamI.(*Stream)
		atomic.StoreUint32(&stream.closed, 1)
		_ = stream.recvBuf.Close() // will not block
		sesh.streams.Delete(key)
		sesh.streamCountDecr()
		return true
	})

	sesh.sb.closeAll()
	log.Debugf("session %v closed gracefully", sesh.id)
	return nil
}

func genRandomPadding() []byte {
	lenB := make([]byte, 1)
	common.CryptoRandRead(lenB)
	pad := make([]byte, lenB[0]+1)
	common.CryptoRandRead(pad)
	return pad
}

func (sesh *Session) Close() error {
	log.Debugf("attempting to actively close session %v", sesh.id)
	if atomic.SwapUint32(&sesh.closed, 1) == 1 {
		log.Debugf("session %v has already been closed", sesh.id)
		return errRepeatSessionClosing
	}
	sesh.acceptCh <- nil

	// close all streams
	sesh.streams.Range(func(key, streamI interface{}) bool {
		if streamI == nil {
			return true
		}
		stream := streamI.(*Stream)
		atomic.StoreUint32(&stream.closed, 1)
		_ = stream.recvBuf.Close() // will not block
		sesh.streams.Delete(key)
		sesh.streamCountDecr()
		return true
	})

	// we send a notice frame telling remote to close the session
	pad := genRandomPadding()
	f := &Frame{
		StreamID: 0xffffffff,
		Seq:      0,
		Closing:  C_SESSION,
		Payload:  pad,
	}
	obfsBuf := make([]byte, len(pad)+HEADER_LEN+sesh.Obfuscator.maxOverhead)
	i, err := sesh.Obfs(f, obfsBuf, 0)
	if err != nil {
		return err
	}
	_, err = sesh.sb.send(obfsBuf[:i], new(uint32))
	if err != nil {
		return err
	}

	sesh.sb.closeAll()
	log.Debugf("session %v closed gracefully", sesh.id)
	return nil
}

func (sesh *Session) IsClosed() bool {
	return atomic.LoadUint32(&sesh.closed) == 1
}

func (sesh *Session) timeoutAfter(to time.Duration) {
	time.Sleep(to)

	if sesh.streamCount() == 0 && !sesh.IsClosed() {
		sesh.SetTerminalMsg("timeout")
		sesh.Close()
	}
}

func (sesh *Session) Addr() net.Addr { return sesh.addrs.Load().([]net.Addr)[0] }
