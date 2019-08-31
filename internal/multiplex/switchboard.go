package multiplex

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
)

const (
	FIXED_CONN_MAPPING switchboardStrategy = iota
	UNIFORM_SPREAD
)

type switchboardConfig struct {
	Valve
	strategy switchboardStrategy
}

// switchboard is responsible for keeping the reference of TLS connections between client and server
type switchboard struct {
	session *Session

	*switchboardConfig

	connsM     sync.RWMutex
	conns      map[uint32]net.Conn
	nextConnId uint32

	broken uint32
}

func makeSwitchboard(sesh *Session, config *switchboardConfig) *switchboard {
	// rates are uint64 because in the usermanager we want the bandwidth to be atomically
	// operated (so that the bandwidth can change on the fly).
	sb := &switchboard{
		session:           sesh,
		switchboardConfig: config,
		conns:             make(map[uint32]net.Conn),
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
func (sb *switchboard) send(data []byte, connId *uint32) (n int, err error) {
	sb.Valve.txWait(len(data))
	sb.connsM.RLock()
	defer sb.connsM.RUnlock()
	if sb.strategy == UNIFORM_SPREAD {
		randConnId := rand.Intn(len(sb.conns))
		conn, ok := sb.conns[uint32(randConnId)]
		if !ok {
			return 0, errBrokenSwitchboard
		} else {
			n, err = conn.Write(data)
			sb.AddTx(int64(n))
			return
		}
	} else {
		var conn net.Conn
		conn, ok := sb.conns[*connId]
		if ok {
			n, err = conn.Write(data)
			sb.AddTx(int64(n))
			return
		} else {
			// do not call assignRandomConn() here.
			// we'll have to do connsM.RLock() after we get a new connId from assignRandomConn, in order to
			// get the new conn through conns[newConnId]
			// however between connsM.RUnlock() in assignRandomConn and our call to connsM.RLock(), things may happen.
			// in particular if newConnId is removed between the RUnlock and RLock, conns[newConnId] will return
			// a nil pointer. To prevent this we must get newConnId and the reference to conn itself in one single mutex
			// protection
			if atomic.LoadUint32(&sb.broken) == 1 || len(sb.conns) == 0 {
				return 0, errBrokenSwitchboard
			}

			r := rand.Intn(len(sb.conns))
			var c int
			for newConnId := range sb.conns {
				if r == c {
					connId = &newConnId
					conn, _ = sb.conns[newConnId]
					n, err = conn.Write(data)
					sb.AddTx(int64(n))
					return
				}
				c++
			}
			return 0, errBrokenSwitchboard
		}
	}

}

// returns a random connId
func (sb *switchboard) assignRandomConn() (uint32, error) {
	sb.connsM.RLock()
	defer sb.connsM.RUnlock()
	if atomic.LoadUint32(&sb.broken) == 1 || len(sb.conns) == 0 {
		return 0, errBrokenSwitchboard
	}

	r := rand.Intn(len(sb.conns))
	var c int
	for connId := range sb.conns {
		if r == c {
			return connId, nil
		}
		c++
	}
	return 0, errBrokenSwitchboard
}

// actively triggered by session.Close()
func (sb *switchboard) closeAll() {
	if atomic.SwapUint32(&sb.broken, 1) == 1 {
		return
	}
	sb.connsM.RLock()
	for key, conn := range sb.conns {
		conn.Close()
		delete(sb.conns, key)
	}
	sb.connsM.RUnlock()
}

// deplex function costantly reads from a TCP connection
func (sb *switchboard) deplex(connId uint32, conn net.Conn) {
	buf := make([]byte, 20480)
	for {
		n, err := sb.session.UnitRead(conn, buf)
		sb.rxWait(n)
		sb.Valve.AddRx(int64(n))
		if err != nil {
			log.Debugf("a connection for session %v has closed: %v", sb.session.id, err)
			go conn.Close()
			sb.removeConn(connId)
			return
		}

		err = sb.session.recvDataFromRemote(buf[:n])
		if err != nil {
			log.Error(err)
		}
	}
}
