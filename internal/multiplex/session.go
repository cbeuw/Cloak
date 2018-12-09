package multiplex

import (
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
)

const (
	// Copied from smux
	acceptBacklog = 1024
)

var ErrBrokenSession = errors.New("broken session")
var errRepeatSessionClosing = errors.New("trying to close a closed session")

type Session struct {
	id uint32 // This field isn't acutally used

	// Used in Stream.Write. Add multiplexing headers, encrypt and add TLS header
	obfs Obfser
	// Remove TLS header, decrypt and unmarshall multiplexing headers
	deobfs Deobfser
	// This is supposed to read one TLS message, the same as GoQuiet's ReadTillDrain
	obfsedRead func(net.Conn, []byte) (int, error)

	// atomic
	nextStreamID uint32

	streamsM sync.RWMutex
	streams  map[uint32]*Stream

	// Switchboard manages all connections to remote
	sb *switchboard

	// For accepting new streams
	acceptCh chan *Stream

	die      chan struct{}
	overdose sync.Once // fentanyl? beware of respiratory depression
}

// 1 conn is needed to make a session
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
	log.Printf("Opening stream %v\n", id)
	return stream, nil
}

func (sesh *Session) AcceptStream() (*Stream, error) {
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
	sesh.streamsM.Unlock()
}

func (sesh *Session) isStream(id uint32) bool {
	sesh.streamsM.RLock()
	_, ok := sesh.streams[id]
	sesh.streamsM.RUnlock()
	return ok
}

// If the stream has been closed and the triggering frame is a closing frame,
// we return nil
func (sesh *Session) getOrAddStream(id uint32, closingFrame bool) *Stream {
	// it would have been neater to use defer Unlock(), however it gives
	// non-negligable overhead and this function is performance critical
	sesh.streamsM.Lock()
	stream := sesh.streams[id]
	if stream != nil {
		sesh.streamsM.Unlock()
		return stream
	} else {
		if closingFrame {
			sesh.streamsM.Unlock()
			return nil
		} else {
			stream = makeStream(id, sesh)
			sesh.streams[id] = stream
			sesh.acceptCh <- stream
			log.Printf("Adding stream %v\n", id)
			sesh.streamsM.Unlock()
			return stream
		}
	}
}

func (sesh *Session) getStream(id uint32) *Stream {
	sesh.streamsM.RLock()
	ret := sesh.streams[id]
	sesh.streamsM.RUnlock()
	return ret
}

// addStream is used when the remote opened a new stream and we got notified
func (sesh *Session) addStream(id uint32) *Stream {
	stream := makeStream(id, sesh)
	sesh.streamsM.Lock()
	sesh.streams[id] = stream
	sesh.streamsM.Unlock()
	sesh.acceptCh <- stream
	log.Printf("Adding stream %v\n", id)
	return stream
}

func (sesh *Session) Close() error {
	// Because closing a closed channel causes panic
	sesh.overdose.Do(func() { close(sesh.die) })
	sesh.streamsM.Lock()
	for id, stream := range sesh.streams {
		// If we call stream.Close() here, streamsM will result in a deadlock
		// because stream.Close calls sesh.delStream, which locks the mutex.
		// so we need to implement a method of stream that closes the stream without calling
		// sesh.delStream
		// This can also be seen in smux
		go stream.closeNoDelMap()
		delete(sesh.streams, id)
	}
	sesh.streamsM.Unlock()

	sesh.sb.shutdown()
	return nil

}
