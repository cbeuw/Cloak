package multiplex

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	FIXED_CONN_MAPPING switchboardStrategy = iota
	UNIFORM_SPREAD
)

// switchboard represents the connection pool. It is responsible for managing
// transport-layer connections between client and server.
// It has several purposes: constantly receiving incoming data from all connections
// and pass them to Session.recvDataFromRemote(); accepting data through
// switchboard.send(), in which it selects a connection according to its
// switchboardStrategy and send the data off using that; and counting, as well as
// rate limiting, data received and sent through its Valve.
type switchboard struct {
	session *Session

	valve    Valve
	strategy switchboardStrategy

	connsM   sync.RWMutex
	conns    []net.Conn
	randPool sync.Pool

	broken uint32
}

func makeSwitchboard(sesh *Session) *switchboard {
	var strategy switchboardStrategy
	if sesh.Unordered {
		log.Debug("Connection is unordered")
		strategy = UNIFORM_SPREAD
	} else {
		strategy = FIXED_CONN_MAPPING
	}
	sb := &switchboard{
		session:  sesh,
		strategy: strategy,
		valve:    sesh.Valve,
		randPool: sync.Pool{New: func() interface{} {
			return rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
		}},
	}
	return sb
}

var errBrokenSwitchboard = errors.New("the switchboard is broken")

func (sb *switchboard) delConn(conn net.Conn) {
	sb.connsM.Lock()
	defer sb.connsM.Unlock()

	if len(sb.conns) <= 1 {
		sb.conns = nil
		return
	}
	var i int
	var c net.Conn
	for i, c = range sb.conns {
		if c == conn {
			break
		}
	}
	sb.conns = append(sb.conns[:i], sb.conns[i+1:]...)
}

func (sb *switchboard) addConn(conn net.Conn) {
	sb.connsM.Lock()
	sb.conns = append(sb.conns, conn)
	sb.connsM.Unlock()
	go sb.deplex(conn)
}

// a pointer to assignedConn is passed here so that the switchboard can reassign it if that conn isn't usable
func (sb *switchboard) send(data []byte, assignedConn *net.Conn) (n int, err error) {
	sb.valve.txWait(len(data))
	if atomic.LoadUint32(&sb.broken) == 1 {
		return 0, errBrokenSwitchboard
	}

	var conn net.Conn
	switch sb.strategy {
	case UNIFORM_SPREAD:
		conn, err = sb.pickRandConn()
		if err != nil {
			return 0, errBrokenSwitchboard
		}
	case FIXED_CONN_MAPPING:
		conn = *assignedConn
	default:
		return 0, errors.New("unsupported traffic distribution strategy")
	}

	if conn != nil {
		n, err = conn.Write(data)
		if err != nil {
			sb.delConn(conn)
		}
	} else {
		conn, err = sb.pickRandConn()
		if err != nil {
			sb.delConn(conn)
			sb.session.SetTerminalMsg("failed to pick a connection " + err.Error())
			sb.session.passiveClose()
			return 0, err
		}
		n, err = conn.Write(data)
		if err != nil {
			sb.delConn(conn)
			sb.session.SetTerminalMsg("failed to send to remote " + err.Error())
			sb.session.passiveClose()
			return n, err
		}
		*assignedConn = conn
	}
	sb.valve.AddTx(int64(n))
	return n, nil
}

// returns a random connId
func (sb *switchboard) pickRandConn() (net.Conn, error) {
	if atomic.LoadUint32(&sb.broken) == 1 {
		return nil, errBrokenSwitchboard
	}

	randReader := sb.randPool.Get().(*rand.Rand)
	sb.connsM.RLock()
	defer sb.connsM.RUnlock()

	connsCount := len(sb.conns)
	if connsCount == 0 {
		return nil, errBrokenSwitchboard
	}
	r := randReader.Intn(connsCount)
	sb.randPool.Put(randReader)

	return sb.conns[r], nil
}

// actively triggered by session.Close()
func (sb *switchboard) closeAll() {
	if !atomic.CompareAndSwapUint32(&sb.broken, 0, 1) {
		return
	}
	sb.connsM.Lock()
	for _, conn := range sb.conns {
		conn.Close()
	}
	sb.conns = nil
	sb.connsM.Unlock()
}

// deplex function costantly reads from a TCP connection
func (sb *switchboard) deplex(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, sb.session.connReceiveBufferSize)
	for {
		n, err := conn.Read(buf)
		sb.valve.rxWait(n)
		sb.valve.AddRx(int64(n))
		if err != nil {
			log.Debugf("a connection for session %v has closed: %v", sb.session.id, err)
			sb.delConn(conn)
			sb.session.SetTerminalMsg("a connection has dropped unexpectedly")
			sb.session.passiveClose()
			return
		}

		err = sb.session.recvDataFromRemote(buf[:n])
		if err != nil {
			log.Error(err)
		}
	}
}
