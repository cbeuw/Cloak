package multiplex

import (
	"errors"
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

type Obfuscator struct {
	// Used in Stream.Write. Add multiplexing headers, encrypt and add TLS header
	Obfs Obfser
	// Remove TLS header, decrypt and unmarshall frames
	Deobfs     Deobfser
	SessionKey []byte
}

type SwitchboardStrategy int

const (
	FixedConnMapping SwitchboardStrategy = iota
	Uniform
)

type SessionConfig struct {
	*Obfuscator

	Valve

	// This is supposed to read one TLS message, the same as GoQuiet's ReadTillDrain
	UnitRead func(net.Conn, []byte) (int, error)

	Unordered bool

	SwitchboardStrategy SwitchboardStrategy
}

type Session struct {
	id uint32

	*SessionConfig

	// atomic
	nextStreamID uint32

	streamsM sync.Mutex
	streams  map[uint32]*Stream

	// Switchboard manages all connections to remote
	sb *switchboard

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
		streams:       make(map[uint32]*Stream),
		acceptCh:      make(chan *Stream, acceptBacklog),
	}
	sesh.addrs.Store([]net.Addr{nil, nil})

	if config.Valve == nil {
		config.Valve = UNLIMITED_VALVE
	}

	sbConfig := &switchboardConfig{
		Valve:     config.Valve,
		unordered: config.Unordered,
		strategy:  config.SwitchboardStrategy,
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
	connId, err := sesh.sb.assignRandomConn()
	if err != nil {
		return nil, err
	}
	stream := makeStream(sesh, id, connId)
	sesh.streamsM.Lock()
	sesh.streams[id] = stream
	sesh.streamsM.Unlock()
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

func (sesh *Session) delStream(id uint32) {
	sesh.streamsM.Lock()
	delete(sesh.streams, id)
	if len(sesh.streams) == 0 {
		log.Tracef("session %v has no active stream left", sesh.id)
		go sesh.timeoutAfter(30 * time.Second)
	}
	sesh.streamsM.Unlock()
}

func (sesh *Session) recvDataFromRemote(data []byte) {
	frame, err := sesh.Deobfs(data)
	if err != nil {
		log.Debugf("Failed to decrypt a frame for session %v: %v", sesh.id, err)
		return
	}

	sesh.streamsM.Lock()
	defer sesh.streamsM.Unlock()
	stream, existing := sesh.streams[frame.StreamID]
	if existing {
		stream.writeFrame(frame)
	} else {
		if frame.Closing == 1 {
			// If the stream has been closed and the current frame is a closing frame, we do noop
			return
		} else {
			// it may be tempting to use the connId from which the frame was received. However it doesn't make
			// any difference because we only care to send the data from the same stream through the same
			// TCP connection. The remote may use a different connection to send the same stream than the one the client
			// use to send.
			connId, _ := sesh.sb.assignRandomConn()
			// we ignore the error here. If the switchboard is broken, it will be reflected upon stream.Write
			stream = makeStream(sesh, frame.StreamID, connId)
			sesh.streams[frame.StreamID] = stream
			sesh.acceptCh <- stream
			stream.writeFrame(frame)
			return
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

func (sesh *Session) Close() error {
	log.Debugf("attempting to close session %v", sesh.id)
	atomic.StoreUint32(&sesh.closed, 1)
	sesh.streamsM.Lock()
	sesh.acceptCh <- nil
	for id, stream := range sesh.streams {
		// If we call stream.Close() here, streamsM will result in a deadlock
		// because stream.Close calls sesh.delStream, which locks the mutex.
		// so we need to implement a method of stream that closes the stream without calling
		// sesh.delStream
		go stream.closeNoDelMap()
		delete(sesh.streams, id)
	}
	sesh.streamsM.Unlock()

	sesh.sb.closeAll()
	log.Debugf("session %v closed gracefully", sesh.id)
	return nil

}

func (sesh *Session) IsClosed() bool {
	return atomic.LoadUint32(&sesh.closed) == 1
}

func (sesh *Session) timeoutAfter(to time.Duration) {
	time.Sleep(to)
	sesh.streamsM.Lock()
	if len(sesh.streams) == 0 && !sesh.IsClosed() {
		sesh.streamsM.Unlock()
		sesh.SetTerminalMsg("timeout")
		sesh.Close()
	} else {
		sesh.streamsM.Unlock()
	}
}

func (sesh *Session) Addr() net.Addr { return sesh.addrs.Load().([]net.Addr)[0] }
