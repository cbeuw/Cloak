package multiplex

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
)

const (
	sentNotifyBacklog = 1024
	dispatchBacklog   = 10240
	newConnBacklog    = 8
)

// switchboard is responsible for keeping the reference of TLS connections between client and server
type switchboard struct {
	session *Session

	optimum atomic.Value
	cesM    sync.RWMutex
	ces     []*connEnclave
}

// Some data comes from a Stream to be sent through one of the many
// remoteConn, but which remoteConn should we use to send the data?
//
// In this case, we pick the remoteConn that has about the smallest sendQueue.
type connEnclave struct {
	sb         *switchboard
	remoteConn net.Conn
	sendQueue  uint32
}

// It takes at least 1 conn to start a switchboard
func makeSwitchboard(conn net.Conn, sesh *Session) *switchboard {
	sb := &switchboard{
		session: sesh,
		ces:     []*connEnclave{},
	}
	ce := &connEnclave{
		sb:         sb,
		remoteConn: conn,
		sendQueue:  0,
	}
	sb.ces = append(sb.ces, ce)
	go sb.deplex(ce)

	return sb
}

func (sb *switchboard) send(data []byte) (int, error) {
	ce := sb.optimum.Load().(*connEnclave)
	atomic.AddUint32(&ce.sendQueue, uint32(len(data)))
	go sb.updateOptimum()
	n, err := ce.remoteConn.Write(data)
	if err != nil {
		return 0, err
		// TODO
	}
	atomic.AddUint32(&ce.sendQueue, ^uint32(n-1))
	go sb.updateOptimum()
	return n, nil
}

func (sb *switchboard) updateOptimum() {
	currentOpti := sb.optimum.Load().(*connEnclave)
	currentOptiQ := atomic.LoadUint32(&currentOpti.sendQueue)
	sb.cesM.RLock()
	for _, ce := range sb.ces {
		ceQ := atomic.LoadUint32(&ce.sendQueue)
		if ceQ < currentOptiQ {
			currentOpti = ce
			currentOptiQ = ceQ
		}
	}
	sb.cesM.RUnlock()
	sb.optimum.Store(currentOpti)
}

func (sb *switchboard) addConn(conn net.Conn) {

	newCe := &connEnclave{
		sb:         sb,
		remoteConn: conn,
		sendQueue:  0,
	}
	sb.cesM.Lock()
	sb.ces = append(sb.ces, newCe)
	sb.cesM.Unlock()
	sb.optimum.Store(newCe)
	go sb.deplex(newCe)
}

func (sb *switchboard) removeConn(closing *connEnclave) {
	sb.cesM.Lock()
	for i, ce := range sb.ces {
		if closing == ce {
			sb.ces = append(sb.ces[:i], sb.ces[i+1:]...)
			break
		}
	}
	sb.cesM.Unlock()
	if len(sb.ces) == 0 {
		sb.session.Close()
	}
}

func (sb *switchboard) shutdown() {
	for _, ce := range sb.ces {
		ce.remoteConn.Close()
	}
}

// deplex function costantly reads from a TCP connection, call deobfs and distribute it
// to the corresponding frame
func (sb *switchboard) deplex(ce *connEnclave) {
	buf := make([]byte, 20480)
	for {
		i, err := sb.session.obfsedReader(ce.remoteConn, buf)
		if err != nil {
			log.Println(err)
			go ce.remoteConn.Close()
			sb.removeConn(ce)
			return
		}
		frame := sb.session.deobfs(buf[:i])
		var stream *Stream
		if stream = sb.session.getStream(frame.StreamID); stream == nil {
			stream = sb.session.addStream(frame.StreamID)
		}
		stream.newFrameCh <- frame
	}
}
