package multiplex

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	acceptBacklog = 1024
)

var ErrBrokenSession = errors.New("broken session")
var errRepeatSessionClosing = errors.New("trying to close a closed session")

// Obfuscator is responsible for the obfuscation and deobfuscation of frames
type Obfuscator struct {
	// Used in Stream.Write. Add multiplexing headers, encrypt and add TLS header
	Obfs Obfser
	// Remove TLS header, decrypt and unmarshall frames
	Deobfs     Deobfser
	SessionKey []byte
}

type switchboardStrategy int

type SessionConfig struct {
	NoRecordLayer bool

	*Obfuscator

	Valve

	// This is supposed to read one TLS message.
	UnitRead func(net.Conn, []byte) (int, error)

	Unordered bool
}

type Session struct {
	id uint32

	*SessionConfig

	// atomic
	nextStreamID uint32

	streams sync.Map

	// Switchboard manages all connections to remote
	sb *switchboard

	// Used for LocalAddr() and RemoteAddr() etc.
	addrs atomic.Value

	// For accepting new streams
	acceptCh chan *Stream

	closed uint32

	terminalMsg atomic.Value
}

func MakeSession(id uint32, config *SessionConfig) *Session {
	sesh := &Session{
		id:            id,
		SessionConfig: config,
		nextStreamID:  1,
		acceptCh:      make(chan *Stream, acceptBacklog),
	}
	sesh.addrs.Store([]net.Addr{nil, nil})

	if config.Valve == nil {
		config.Valve = UNLIMITED_VALVE
	}

	sbConfig := &switchboardConfig{
		Valve: config.Valve,
	}
	if config.Unordered {
		log.Debug("Connection is unordered")
		sbConfig.strategy = UNIFORM_SPREAD
	} else {
		sbConfig.strategy = FIXED_CONN_MAPPING
	}
	sesh.sb = makeSwitchboard(sesh, sbConfig)
	go sesh.timeoutAfter(30 * time.Second)
	return sesh
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
	connId, _, err := sesh.sb.pickRandConn()
	if err != nil {
		return nil, err
	}
	stream := makeStream(sesh, id, connId)
	sesh.streams.Store(id, stream)
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
	if s.isClosed() {
		return errors.New("Already Closed")
	}
	atomic.StoreUint32(&s.closed, 1)
	_ = s.recvBuf.Close() // both datagramBuffer and streamBuffer won't return err on Close()

	if active {
		s.writingM.Lock()
		defer s.writingM.Unlock()
		// Notify remote that this stream is closed
		pad := genRandomPadding()
		f := &Frame{
			StreamID: s.id,
			Seq:      atomic.AddUint64(&s.nextSendSeq, 1) - 1,
			Closing:  C_STREAM,
			Payload:  pad,
		}
		i, err := s.session.Obfs(f, s.obfsBuf)
		if err != nil {
			return err
		}
		_, err = s.session.sb.send(s.obfsBuf[:i], &s.assignedConnId)
		if err != nil {
			return err
		}
		log.Tracef("stream %v actively closed", s.id)
	} else {
		log.Tracef("stream %v passively closed", s.id)
	}

	sesh.streams.Delete(s.id)
	var count int
	sesh.streams.Range(func(_, _ interface{}) bool {
		count += 1
		return true
	})
	if count == 0 {
		log.Tracef("session %v has no active stream left", sesh.id)
		go sesh.timeoutAfter(30 * time.Second)
	}
	return nil
}

// recvDataFromRemote deobfuscate the frame and send it to the appropriate stream buffer
func (sesh *Session) recvDataFromRemote(data []byte) error {
	frame, err := sesh.Deobfs(data)
	if err != nil {
		return fmt.Errorf("Failed to decrypt a frame for session %v: %v", sesh.id, err)
	}

	streamI, existing := sesh.streams.Load(frame.StreamID)
	if existing {
		stream := streamI.(*Stream)
		return stream.writeFrame(*frame)
	} else {
		if frame.Closing == C_STREAM {
			// If the stream has been closed and the current frame is a closing frame, we do noop
			return nil
		} else if frame.Closing == C_SESSION {
			// Closing session
			sesh.SetTerminalMsg("Received a closing notification frame")
			return sesh.passiveClose()
		} else {
			// it may be tempting to use the connId from which the frame was received. However it doesn't make
			// any difference because we only care to send the data from the same stream through the same
			// TCP connection. The remote may use a different connection to send the same stream than the one the client
			// use to send.
			connId, _, _ := sesh.sb.pickRandConn()
			// we ignore the error here. If the switchboard is broken, it will be reflected upon stream.Write
			stream := makeStream(sesh, frame.StreamID, connId)
			sesh.streams.Store(stream.id, stream)
			sesh.acceptCh <- stream
			return stream.writeFrame(*frame)
		}
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
		stream := streamI.(*Stream)
		atomic.StoreUint32(&stream.closed, 1)
		_ = stream.recvBuf.Close() // will not block
		sesh.streams.Delete(key)
		return true
	})

	sesh.sb.closeAll()
	log.Debugf("session %v closed gracefully", sesh.id)
	return nil
}

func genRandomPadding() []byte {
	lenB := make([]byte, 1)
	rand.Read(lenB)
	pad := make([]byte, lenB[0])
	rand.Read(pad)
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
		stream := streamI.(*Stream)
		atomic.StoreUint32(&stream.closed, 1)
		_ = stream.recvBuf.Close() // will not block
		sesh.streams.Delete(key)
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
	i, err := sesh.Obfs(f, obfsBuf)
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
	var count int
	sesh.streams.Range(func(_, _ interface{}) bool {
		count += 1
		return true
	})
	if count == 0 && !sesh.IsClosed() {
		sesh.SetTerminalMsg("timeout")
		sesh.Close()
	}
}

func (sesh *Session) Addr() net.Addr { return sesh.addrs.Load().([]net.Addr)[0] }
