package multiplex

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
)

// switchboard is responsible for keeping the reference of TLS connections between client and server
type switchboard struct {
	session *Session

	*Valve

	connsM     sync.RWMutex
	conns      map[uint32]net.Conn
	nextConnId uint32

	broken uint32
}

func makeSwitchboard(sesh *Session, valve *Valve) *switchboard {
	// rates are uint64 because in the usermanager we want the bandwidth to be atomically
	// operated (so that the bandwidth can change on the fly).
	sb := &switchboard{
		session: sesh,
		Valve:   valve,
		conns:   make(map[uint32]net.Conn),
	}
	return sb
}

var errNilOptimum = errors.New("The optimal connection is nil")
var errBrokenSwitchboard = errors.New("the switchboard is broken")

func (sb *switchboard) addConn(conn net.Conn) {
	connId := atomic.AddUint32(&sb.nextConnId, 1) - 1
	sb.connsM.Lock()
	sb.conns[connId] = conn
	sb.connsM.Unlock()
	go sb.deplex(connId, conn)
}

func (sb *switchboard) removeConn(connId uint32) {
	sb.connsM.Lock()
	delete(sb.conns, connId)
	remaining := len(sb.conns)
	sb.connsM.Unlock()
	if remaining == 0 {
		atomic.StoreUint32(&sb.broken, 1)
		sb.session.SetTerminalMsg("no underlying connection left")
		sb.session.Close()
	}
}

// a pointer to connId is passed here so that the switchboard can reassign it
func (sb *switchboard) send(data []byte, connId *uint32) (int, error) {
	var conn net.Conn
	sb.connsM.RLock()
	conn, ok := sb.conns[*connId]
	sb.connsM.RUnlock()
	if ok {
		return conn.Write(data)
	} else {
		// do not call assignRandomConn() here.
		// we'll have to do connsM.RLock() after we get a new connId from assignRandomConn, in order to
		// get the new conn through conns[newConnId]
		// however between connsM.RUnlock() in assignRandomConn and our call to connsM.RLock(), things may happen.
		// in particular if newConnId is removed between the RUnlock and RLock, conns[newConnId] will return
		// a nil pointer. To prevent this we must get newConnId and the reference to conn itself in one single mutex
		// protection
		if atomic.LoadUint32(&sb.broken) == 1 {
			return 0, errBrokenSwitchboard
		}
		sb.connsM.RLock()
		newConnId := rand.Intn(len(sb.conns))
		conn = sb.conns[uint32(newConnId)]
		sb.connsM.RUnlock()
		return conn.Write(data)
	}

}

func (sb *switchboard) assignRandomConn() (uint32, error) {
	if atomic.LoadUint32(&sb.broken) == 1 {
		return 0, errBrokenSwitchboard
	}
	sb.connsM.RLock()
	connId := rand.Intn(len(sb.conns))
	sb.connsM.RUnlock()
	return uint32(connId), nil
}

// actively triggered by session.Close()
func (sb *switchboard) closeAll() {
	if atomic.SwapUint32(&sb.broken, 1) == 1 {
		return
	}
	sb.connsM.RLock()
	for _, conn := range sb.conns {
		conn.Close()
	}
	sb.connsM.RUnlock()
}

// deplex function costantly reads from a TCP connection
func (sb *switchboard) deplex(connId uint32, conn net.Conn) {
	buf := make([]byte, 20480)
	for {
		n, err := sb.session.unitRead(conn, buf)
		sb.rxWait(n)
		sb.Valve.AddRx(int64(n))
		if err != nil {
			log.Tracef("a connection for session %v has closed: %v", sb.session.id, err)
			go conn.Close()
			sb.removeConn(connId)
			return
		}

		sb.session.recvDataFromRemote(buf[:n])
	}
}
