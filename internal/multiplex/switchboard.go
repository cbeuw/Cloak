package multiplex

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"net"
	"sync"
	"sync/atomic"
)

// switchboard is responsible for keeping the reference of TLS connections between client and server
type switchboard struct {
	session *Session

	*Valve

	// optimum is the connEnclave with the smallest sendQueue
	optimum atomic.Value // *connEnclave
	cesM    sync.RWMutex
	ces     []*connEnclave

	broken uint32
}

func (sb *switchboard) getOptimum() *connEnclave {
	if i := sb.optimum.Load(); i == nil {
		return nil
	} else {
		return i.(*connEnclave)
	}
}

// Some data comes from a Stream to be sent through one of the many
// remoteConn, but which remoteConn should we use to send the data?
//
// In this case, we pick the remoteConn that has about the smallest sendQueue.
type connEnclave struct {
	remoteConn net.Conn
	sendQueue  uint32
}

func makeSwitchboard(sesh *Session, valve *Valve) *switchboard {
	// rates are uint64 because in the usermanager we want the bandwidth to be atomically
	// operated (so that the bandwidth can change on the fly).
	sb := &switchboard{
		session: sesh,
		Valve:   valve,
		ces:     []*connEnclave{},
	}
	return sb
}

var errNilOptimum = errors.New("The optimal connection is nil")
var errBrokenSwitchboard = errors.New("the switchboard is broken")

func (sb *switchboard) Write(data []byte) (int, error) {
	if atomic.LoadUint32(&sb.broken) == 1 {
		return 0, errBrokenSwitchboard
	}
	ce := sb.getOptimum()
	if ce == nil {
		return 0, errNilOptimum
	}
	atomic.AddUint32(&ce.sendQueue, uint32(len(data)))
	go sb.updateOptimum()
	n, err := ce.remoteConn.Write(data)
	if err != nil {
		return n, err
	}
	sb.txWait(n)
	sb.Valve.AddTx(int64(n))
	atomic.AddUint32(&ce.sendQueue, ^uint32(n-1))
	go sb.updateOptimum()
	return n, nil
}

func (sb *switchboard) updateOptimum() {
	currentOpti := sb.getOptimum()
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
	var sendQueue uint32
	newCe := &connEnclave{
		remoteConn: conn,
		sendQueue:  sendQueue,
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
	remaining := len(sb.ces)
	sb.cesM.Unlock()
	if remaining == 0 {
		atomic.StoreUint32(&sb.broken, 1)
		sb.session.SetTerminalMsg("no underlying connection left")
		sb.session.Close()
	}
}

// actively triggered by session.Close()
func (sb *switchboard) closeAll() {
	if atomic.SwapUint32(&sb.broken, 1) == 1 {
		return
	}
	sb.cesM.RLock()
	for _, ce := range sb.ces {
		ce.remoteConn.Close()
	}
	sb.cesM.RUnlock()
}

// deplex function costantly reads from a TCP connection
func (sb *switchboard) deplex(ce *connEnclave) {
	buf := make([]byte, 20480)
	for {
		n, err := sb.session.unitRead(ce.remoteConn, buf)
		sb.rxWait(n)
		sb.Valve.AddRx(int64(n))
		if err != nil {
			log.Tracef("a connection for session %v has closed: %v", sb.session.id, err)
			go ce.remoteConn.Close()
			sb.removeConn(ce)
			return
		}

		sb.session.recvDataFromRemote(buf[:n])
	}
}
