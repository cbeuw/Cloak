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

	// Valve is used to limit transmission rates, and record and limit usage
	Valve

	Unordered bool

	// A Singleplexing session always has just one stream
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

// A Session represents a self-contained communication chain between local and remote. It manages its streams,
// controls serialisation and encryption of data sent and received using the supplied Obfuscator, and send and receive
// data through a manged connection pool filled with underlying connections added to it.
type Session struct {
	id uint32

	SessionConfig

	// atomic
	nextStreamID uint32

	// atomic
	activeStreamCount uint32

	streamsM sync.Mutex
	streams  map[uint32]*Stream

	// a pool of heap allocated frame objects so we don't have to allocate a new one each time we receive a frame
	recvFramePool sync.Pool

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
		recvFramePool: sync.Pool{New: func() interface{} { return &Frame{} }},
		streams:       map[uint32]*Stream{},
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
	sesh.maxStreamUnitWrite = sesh.MsgOnWireSizeLimit - frameHeaderLength - sesh.Obfuscator.maxOverhead

	sesh.sb = makeSwitchboard(sesh)
	time.AfterFunc(sesh.InactivityTimeout, sesh.checkTimeout)
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

// AddConnection is used to add an underlying connection to the connection pool
func (sesh *Session) AddConnection(conn net.Conn) {
	sesh.sb.addConn(conn)
	addrs := []net.Addr{conn.LocalAddr(), conn.RemoteAddr()}
	sesh.addrs.Store(addrs)
}

// OpenStream is similar to net.Dial. It opens up a new stream
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
	sesh.streamsM.Lock()
	sesh.streams[id] = stream
	sesh.streamsM.Unlock()
	sesh.streamCountIncr()
	log.Tracef("stream %v of session %v opened", id, sesh.id)
	return stream, nil
}

// Accept is similar to net.Listener's Accept(). It blocks and returns an incoming stream
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
	// must be holding s.wirtingM on entry
	if atomic.SwapUint32(&s.closed, 1) == 1 {
		return fmt.Errorf("closing stream %v: %w", s.id, errRepeatStreamClosing)
	}
	_ = s.getRecvBuf().Close() // recvBuf.Close should not return error

	if active {
		// Notify remote that this stream is closed
		padding := genRandomPadding()
		s.writingFrame.Closing = closingStream
		s.writingFrame.Payload = padding

		obfsBuf := make([]byte, len(padding)+frameHeaderLength+sesh.Obfuscator.maxOverhead)

		i, err := sesh.Obfs(&s.writingFrame, obfsBuf, 0)
		s.writingFrame.Seq++
		if err != nil {
			return err
		}
		_, err = sesh.sb.send(obfsBuf[:i], &s.assignedConnId)
		if err != nil {
			return err
		}
		log.Tracef("stream %v actively closed.", s.id)
	} else {
		log.Tracef("stream %v passively closed", s.id)
	}

	// We set it as nil to signify that the stream id had existed before.
	// If we Delete(s.id) straight away, later on in recvDataFromRemote, it will not be able to tell
	// if the frame it received was from a new stream or a dying stream whose frame arrived late
	sesh.streamsM.Lock()
	sesh.streams[s.id] = nil
	sesh.streamsM.Unlock()
	if sesh.streamCountDecr() == 0 {
		if sesh.Singleplex {
			return sesh.Close()
		} else {
			log.Debugf("session %v has no active stream left", sesh.id)
			time.AfterFunc(sesh.InactivityTimeout, sesh.checkTimeout)
		}
	}
	return nil
}

// recvDataFromRemote deobfuscate the frame and read the Closing field. If it is a closing frame, it writes the frame
// to the stream buffer, otherwise it fetches the desired stream instance, or creates and stores one if it's a new
// stream and then writes to the stream buffer
func (sesh *Session) recvDataFromRemote(data []byte) error {
	frame := sesh.recvFramePool.Get().(*Frame)
	defer sesh.recvFramePool.Put(frame)

	err := sesh.Deobfs(frame, data)
	if err != nil {
		return fmt.Errorf("Failed to decrypt a frame for session %v: %v", sesh.id, err)
	}

	if frame.Closing == closingSession {
		sesh.SetTerminalMsg("Received a closing notification frame")
		return sesh.passiveClose()
	}

	sesh.streamsM.Lock()
	existingStream, existing := sesh.streams[frame.StreamID]
	if existing {
		sesh.streamsM.Unlock()
		if existingStream == nil {
			// this is when the stream existed before but has since been closed. We do nothing
			return nil
		}
		return existingStream.recvFrame(frame)
	} else {
		newStream := makeStream(sesh, frame.StreamID)
		sesh.streams[frame.StreamID] = newStream
		sesh.streamsM.Unlock()
		// new stream
		sesh.streamCountIncr()
		sesh.acceptCh <- newStream
		return newStream.recvFrame(frame)
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

func (sesh *Session) closeSession(closeSwitchboard bool) error {
	if atomic.SwapUint32(&sesh.closed, 1) == 1 {
		log.Debugf("session %v has already been closed", sesh.id)
		return errRepeatSessionClosing
	}
	sesh.acceptCh <- nil

	sesh.streamsM.Lock()
	for id, stream := range sesh.streams {
		if stream == nil {
			continue
		}
		atomic.StoreUint32(&stream.closed, 1)
		_ = stream.getRecvBuf().Close() // will not block
		delete(sesh.streams, id)
		sesh.streamCountDecr()
	}
	sesh.streamsM.Unlock()

	if closeSwitchboard {
		sesh.sb.closeAll()
	}
	return nil
}

func (sesh *Session) passiveClose() error {
	log.Debugf("attempting to passively close session %v", sesh.id)
	err := sesh.closeSession(true)
	if err != nil {
		return err
	}
	log.Debugf("session %v closed gracefully", sesh.id)
	return nil
}

func genRandomPadding() []byte {
	lenB := make([]byte, 1)
	common.CryptoRandRead(lenB)
	pad := make([]byte, int(lenB[0])+1)
	common.CryptoRandRead(pad)
	return pad
}

func (sesh *Session) Close() error {
	log.Debugf("attempting to actively close session %v", sesh.id)
	err := sesh.closeSession(false)
	if err != nil {
		return err
	}
	// we send a notice frame telling remote to close the session
	pad := genRandomPadding()
	f := &Frame{
		StreamID: 0xffffffff,
		Seq:      0,
		Closing:  closingSession,
		Payload:  pad,
	}
	obfsBuf := make([]byte, len(pad)+frameHeaderLength+sesh.Obfuscator.maxOverhead)
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

func (sesh *Session) checkTimeout() {
	if sesh.streamCount() == 0 && !sesh.IsClosed() {
		sesh.SetTerminalMsg("timeout")
		sesh.Close()
	}
}

func (sesh *Session) Addr() net.Addr { return sesh.addrs.Load().([]net.Addr)[0] }
