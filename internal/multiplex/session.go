package multiplex

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cbeuw/Cloak/internal/common"

	log "github.com/sirupsen/logrus"
)

const (
	acceptBacklog            = 1024
	defaultInactivityTimeout = 30 * time.Second
	defaultMaxOnWireSize     = 1<<14 + 256 // https://tools.ietf.org/html/rfc8446#section-5.2
)

var ErrBrokenSession = errors.New("broken session")
var errRepeatSessionClosing = errors.New("trying to close a closed session")
var errRepeatStreamClosing = errors.New("trying to close a closed stream")
var errNoMultiplex = errors.New("a singleplexing session can have only one stream")

type SessionConfig struct {
	Obfuscator

	// Valve is used to limit transmission rates, and record and limit usage
	Valve

	Unordered bool

	// A Singleplexing session always has just one stream
	Singleplex bool

	// maximum size of an obfuscated frame, including headers and overhead
	MsgOnWireSizeLimit int

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
	// For accepting new streams
	acceptCh chan *Stream

	// a pool of heap allocated frame objects so we don't have to allocate a new one each time we receive a frame
	recvFramePool sync.Pool

	streamObfsBufPool sync.Pool

	// Switchboard manages all connections to remote
	sb *switchboard

	// Used for LocalAddr() and RemoteAddr() etc.
	addrs atomic.Value

	closed uint32

	terminalMsgSetter sync.Once
	terminalMsg       string

	// the max size passed to Write calls before it splits it into multiple frames
	// i.e. the max size a piece of data can fit into a Frame.Payload
	maxStreamUnitWrite int
	// streamSendBufferSize sets the buffer size used to send data from a Stream (Stream.obfsBuf)
	streamSendBufferSize int
	// connReceiveBufferSize sets the buffer size used to receive data from an underlying Conn (allocated in
	// switchboard.deplex)
	connReceiveBufferSize int
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
	if config.MsgOnWireSizeLimit <= 0 {
		sesh.MsgOnWireSizeLimit = defaultMaxOnWireSize
	}
	if config.InactivityTimeout == 0 {
		sesh.InactivityTimeout = defaultInactivityTimeout
	}

	sesh.maxStreamUnitWrite = sesh.MsgOnWireSizeLimit - frameHeaderLength - maxExtraLen
	sesh.streamSendBufferSize = sesh.MsgOnWireSizeLimit
	sesh.connReceiveBufferSize = 20480 // for backwards compatibility

	sesh.streamObfsBufPool = sync.Pool{New: func() interface{} {
		b := make([]byte, sesh.streamSendBufferSize)
		return &b
	}}

	sesh.sb = makeSwitchboard(sesh)
	time.AfterFunc(sesh.InactivityTimeout, sesh.checkTimeout)
	return sesh
}

func (sesh *Session) GetSessionKey() [32]byte {
	return sesh.sessionKey
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
	if !atomic.CompareAndSwapUint32(&s.closed, 0, 1) {
		return fmt.Errorf("closing stream %v: %w", s.id, errRepeatStreamClosing)
	}
	_ = s.recvBuf.Close() // recvBuf.Close should not return error

	if active {
		tmpBuf := sesh.streamObfsBufPool.Get().(*[]byte)

		// Notify remote that this stream is closed
		common.CryptoRandRead((*tmpBuf)[:1])
		padLen := int((*tmpBuf)[0]) + 1
		payload := (*tmpBuf)[frameHeaderLength : padLen+frameHeaderLength]
		common.CryptoRandRead(payload)

		// must be holding s.wirtingM on entry
		s.writingFrame.Closing = closingStream
		s.writingFrame.Payload = payload

		err := s.obfuscateAndSend(*tmpBuf, frameHeaderLength)
		sesh.streamObfsBufPool.Put(tmpBuf)
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

	err := sesh.deobfuscate(frame, data)
	if err != nil {
		return fmt.Errorf("Failed to decrypt a frame for session %v: %v", sesh.id, err)
	}

	if frame.Closing == closingSession {
		sesh.SetTerminalMsg("Received a closing notification frame")
		return sesh.passiveClose()
	}

	sesh.streamsM.Lock()
	if sesh.IsClosed() {
		sesh.streamsM.Unlock()
		return ErrBrokenSession
	}
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
		sesh.acceptCh <- newStream
		sesh.streamsM.Unlock()
		// new stream
		sesh.streamCountIncr()
		return newStream.recvFrame(frame)
	}
}

func (sesh *Session) SetTerminalMsg(msg string) {
	log.Debug("terminal message set to " + msg)
	sesh.terminalMsgSetter.Do(func() {
		sesh.terminalMsg = msg
	})
}

func (sesh *Session) TerminalMsg() string {
	return sesh.terminalMsg
}

func (sesh *Session) closeSession() error {
	if !atomic.CompareAndSwapUint32(&sesh.closed, 0, 1) {
		log.Debugf("session %v has already been closed", sesh.id)
		return errRepeatSessionClosing
	}

	sesh.streamsM.Lock()
	close(sesh.acceptCh)
	for id, stream := range sesh.streams {
		if stream != nil && atomic.CompareAndSwapUint32(&stream.closed, 0, 1) {
			_ = stream.recvBuf.Close() // will not block
			delete(sesh.streams, id)
			sesh.streamCountDecr()
		}
	}
	sesh.streamsM.Unlock()
	return nil
}

func (sesh *Session) passiveClose() error {
	log.Debugf("attempting to passively close session %v", sesh.id)
	err := sesh.closeSession()
	if err != nil {
		return err
	}
	sesh.sb.closeAll()
	log.Debugf("session %v closed gracefully", sesh.id)
	return nil
}

func (sesh *Session) Close() error {
	log.Debugf("attempting to actively close session %v", sesh.id)
	err := sesh.closeSession()
	if err != nil {
		return err
	}
	// we send a notice frame telling remote to close the session

	buf := sesh.streamObfsBufPool.Get().(*[]byte)
	common.CryptoRandRead((*buf)[:1])
	padLen := int((*buf)[0]) + 1
	payload := (*buf)[frameHeaderLength : padLen+frameHeaderLength]
	common.CryptoRandRead(payload)

	f := &Frame{
		StreamID: 0xffffffff,
		Seq:      0,
		Closing:  closingSession,
		Payload:  payload,
	}
	i, err := sesh.obfuscate(f, *buf, frameHeaderLength)
	if err != nil {
		return err
	}
	_, err = sesh.sb.send((*buf)[:i], new(net.Conn))
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
