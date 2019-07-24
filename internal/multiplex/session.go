package multiplex

import (
	"errors"
	//"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	acceptBacklog = 1024
)

var ErrBrokenSession = errors.New("broken session")
var errRepeatSessionClosing = errors.New("trying to close a closed session")

type Session struct {
	id uint32

	// Used in Stream.Write. Add multiplexing headers, encrypt and add TLS header
	obfs Obfser
	// Remove TLS header, decrypt and unmarshall multiplexing headers
	deobfs Deobfser
	// This is supposed to read one TLS message, the same as GoQuiet's ReadTillDrain
	obfsedRead func(net.Conn, []byte) (int, error)

	// atomic
	nextStreamID uint32

	streamsM sync.Mutex
	streams  map[uint32]*Stream

	// Switchboard manages all connections to remote
	sb *switchboard

	// For accepting new streams
	acceptCh chan *Stream

	broken  uint32
	die     chan struct{}
	suicide sync.Once

	terminalMsg atomic.Value
}

func MakeSession(id uint32, valve *Valve, obfs Obfser, deobfs Deobfser, obfsedRead func(net.Conn, []byte) (int, error)) *Session {
	sesh := &Session{
		id:           id,
		obfs:         obfs,
		deobfs:       deobfs,
		obfsedRead:   obfsedRead,
		nextStreamID: 1,
		streams:      make(map[uint32]*Stream),
		acceptCh:     make(chan *Stream, acceptBacklog),
		die:          make(chan struct{}),
	}
	sesh.sb = makeSwitchboard(sesh, valve)
	go sesh.timeoutAfter(30 * time.Second)
	return sesh
}

func (sesh *Session) AddConnection(conn net.Conn) {
	sesh.sb.addConn(conn)
}

func (sesh *Session) OpenStream() (*Stream, error) {
	select {
	case <-sesh.die:
		return nil, ErrBrokenSession
	default:
	}
	id := atomic.AddUint32(&sesh.nextStreamID, 1) - 1
	// Because atomic.AddUint32 returns the value after incrementation
	stream := makeStream(id, sesh)
	sesh.streamsM.Lock()
	sesh.streams[id] = stream
	sesh.streamsM.Unlock()
	//log.Printf("Opening stream %v\n", id)
	return stream, nil
}

func (sesh *Session) Accept() (net.Conn, error) {
	select {
	case <-sesh.die:
		return nil, ErrBrokenSession
	case stream := <-sesh.acceptCh:
		return stream, nil
	}

}

func (sesh *Session) delStream(id uint32) {
	sesh.streamsM.Lock()
	delete(sesh.streams, id)
	if len(sesh.streams) == 0 {
		go sesh.timeoutAfter(30 * time.Second)
	}
	sesh.streamsM.Unlock()
}

// either fetch an existing stream or instantiate a new stream and put it in the dict, and return it
func (sesh *Session) getStream(id uint32, closingFrame bool) *Stream {
	// it would have been neater to use defer Unlock(), however it gives
	// non-negligable overhead and this function is performance critical
	sesh.streamsM.Lock()
	stream := sesh.streams[id]
	if stream != nil {
		sesh.streamsM.Unlock()
		return stream
	} else {
		if closingFrame {
			// If the stream has been closed and the current frame is a closing frame,
			// we return nil
			sesh.streamsM.Unlock()
			return nil
		} else {
			stream = makeStream(id, sesh)
			sesh.streams[id] = stream
			sesh.acceptCh <- stream
			//log.Printf("Adding stream %v\n", id)
			sesh.streamsM.Unlock()
			return stream
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
	// Because closing a closed channel causes panic
	sesh.suicide.Do(func() { close(sesh.die) })
	atomic.StoreUint32(&sesh.broken, 1)
	sesh.streamsM.Lock()
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
	return nil

}

func (sesh *Session) IsBroken() bool {
	return atomic.LoadUint32(&sesh.broken) == 1
}

func (sesh *Session) timeoutAfter(to time.Duration) {
	time.Sleep(to)
	sesh.streamsM.Lock()
	if len(sesh.streams) == 0 && !sesh.IsBroken() {
		sesh.streamsM.Unlock()
		sesh.Close()
	} else {
		sesh.streamsM.Unlock()
	}
}

// Addr is only for implementing net.Listener
func (sesh *Session) Addr() net.Addr { return nil }
