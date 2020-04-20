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
	defaultSendRecvBufSize = 20480
)

var ErrBrokenSession = errors.New("broken session")
var errRepeatSessionClosing = errors.New("trying to close a closed session")
var errRepeatStreamClosing = errors.New("trying to close a closed stream")

type switchboardStrategy int

type SessionConfig struct {
	Obfuscator

	Valve

	Unordered bool

	MaxFrameSize      int // maximum size of the frame, including the header
	SendBufferSize    int
	ReceiveBufferSize int
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

	maxStreamUnitWrite int // the max size passed to Write calls before it splits it into multiple frames
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
	if config.SendBufferSize <= 0 {
		sesh.SendBufferSize = defaultSendRecvBufSize
	}
	if config.ReceiveBufferSize <= 0 {
		sesh.ReceiveBufferSize = defaultSendRecvBufSize
	}
	if config.MaxFrameSize <= 0 {
		sesh.MaxFrameSize = defaultSendRecvBufSize - 1024
	}
	// todo: validation. this must be smaller than the buffer sizes
	sesh.maxStreamUnitWrite = sesh.MaxFrameSize - HEADER_LEN - sesh.Obfuscator.minOverhead

	sbConfig := switchboardConfig{
		valve:          sesh.Valve,
		recvBufferSize: sesh.ReceiveBufferSize,
	}
	if sesh.Unordered {
		log.Debug("Connection is unordered")
		sbConfig.strategy = UNIFORM_SPREAD
	} else {
		sbConfig.strategy = FIXED_CONN_MAPPING
	}
	sesh.sb = makeSwitchboard(sesh, sbConfig)
	go sesh.timeoutAfter(30 * time.Second)
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
	_ = s.recvBuf.Close() // both datagramBuffer and streamBuffer won't return err on Close()

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

		obfsBuf := make([]byte, len(padding)+64)
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

	sesh.streams.Store(s.id, nil) // id may or may not exist. if we use Delete(s.id) here it will panic
	if sesh.streamCountDecr() == 0 {
		log.Debugf("session %v has no active stream left", sesh.id)
		go sesh.timeoutAfter(30 * time.Second)
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
		return existingStreamI.(*Stream).writeFrame(*frame)
	} else {
		// new stream
		sesh.streamCountIncr()
		sesh.acceptCh <- newStream
		return newStream.writeFrame(*frame)
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
	pad := make([]byte, lenB[0])
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

	pad := genRandomPadding()
	f := &Frame{
		StreamID: 0xffffffff,
		Seq:      0,
		Closing:  C_SESSION,
		Payload:  pad,
	}
	obfsBuf := make([]byte, len(pad)+64)
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
