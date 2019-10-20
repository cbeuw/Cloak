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

// switchboard is responsible for keeping the reference of TCP connections between client and server
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

// a pointer to connId is passed here so that the switchboard can reassign it
func (sb *switchboard) send(data []byte, connId *uint32) (n int, err error) {
	writeAndRegUsage := func(conn net.Conn, d []byte) (int, error) {
		n, err = conn.Write(d)
		if err != nil {
			sb.close("failed to write to remote " + err.Error())
			return n, err
		}
		sb.AddTx(int64(n))
		return n, nil
	}

	sb.Valve.txWait(len(data))
	sb.connsM.RLock()
	defer sb.connsM.RUnlock()
	if atomic.LoadUint32(&sb.broken) == 1 || len(sb.conns) == 0 {
		return 0, errBrokenSwitchboard
	}

	if sb.strategy == UNIFORM_SPREAD {
		r := rand.Intn(len(sb.conns))
		var c int
		for newConnId := range sb.conns {
			if r == c {
				conn, _ := sb.conns[newConnId]
				return writeAndRegUsage(conn, data)
			}
			c++
		}
		return 0, errBrokenSwitchboard
	} else {
		var conn net.Conn
		conn, ok := sb.conns[*connId]
		if ok {
			return writeAndRegUsage(conn, data)
		} else {
			// do not call assignRandomConn() here.
			// we'll have to do connsM.RLock() after we get a new connId from assignRandomConn, in order to
			// get the new conn through conns[newConnId]
			// however between connsM.RUnlock() in assignRandomConn and our call to connsM.RLock(), things may happen.
			// in particular if newConnId is removed between the RUnlock and RLock, conns[newConnId] will return
			// a nil pointer. To prevent this we must get newConnId and the reference to conn itself in one single mutex
			// protection
			r := rand.Intn(len(sb.conns))
			var c int
			for newConnId := range sb.conns {
				if r == c {
					connId = &newConnId
					conn, _ = sb.conns[newConnId]
					return writeAndRegUsage(conn, data)
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

func (sb *switchboard) close(terminalMsg string) {
	atomic.StoreUint32(&sb.broken, 1)
	if !sb.session.IsClosed() {
		sb.session.SetTerminalMsg(terminalMsg)
		sb.session.passiveClose()
	}
}

// actively triggered by session.Close()
func (sb *switchboard) closeAll() {
	sb.connsM.Lock()
	for key, conn := range sb.conns {
		conn.Close()
		delete(sb.conns, key)
	}
	sb.connsM.Unlock()
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
			sb.close("a connection has dropped unexpectedly")
			return
		}

		err = sb.session.recvDataFromRemote(buf[:n])
		if err != nil {
			log.Error(err)
		}
	}
}
