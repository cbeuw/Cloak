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

// switchboard is responsible for managing TCP connections between client and server.
// It has several purposes: constantly receiving incoming data from all connections
// and pass them to Session.recvDataFromRemote(); accepting data through
// switchboard.send(), in which it selects a connection according to its
// switchboardStrategy and send the data off using that; and counting, as well as
// rate limiting, data received and sent through its Valve.
type switchboard struct {
	session *Session

	valve    Valve
	strategy switchboardStrategy

	// map of connId to net.Conn
	conns      sync.Map
	numConns   uint32
	nextConnId uint32

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
		session:    sesh,
		strategy:   strategy,
		valve:      sesh.Valve,
		nextConnId: 1,
	}
	return sb
}

var errBrokenSwitchboard = errors.New("the switchboard is broken")

func (sb *switchboard) connsCount() int {
	return int(atomic.LoadUint32(&sb.numConns))
}

func (sb *switchboard) addConn(conn net.Conn) {
	connId := atomic.AddUint32(&sb.nextConnId, 1) - 1
	atomic.AddUint32(&sb.numConns, 1)
	sb.conns.Store(connId, conn)
	go sb.deplex(connId, conn)
}

// a pointer to connId is passed here so that the switchboard can reassign it if that connId isn't usable
func (sb *switchboard) send(data []byte, connId *uint32) (n int, err error) {
	writeAndRegUsage := func(conn net.Conn, d []byte) (int, error) {
		n, err = conn.Write(d)
		if err != nil {
			sb.conns.Delete(*connId)
			sb.close("failed to write to remote " + err.Error())
			return n, err
		}
		sb.valve.AddTx(int64(n))
		return n, nil
	}

	sb.valve.txWait(len(data))
	if atomic.LoadUint32(&sb.broken) == 1 || sb.connsCount() == 0 {
		return 0, errBrokenSwitchboard
	}

	switch sb.strategy {
	case UNIFORM_SPREAD:
		_, conn, err := sb.pickRandConn()
		if err != nil {
			return 0, errBrokenSwitchboard
		}
		return writeAndRegUsage(conn, data)
	case FIXED_CONN_MAPPING:
		connI, ok := sb.conns.Load(*connId)
		if ok {
			conn := connI.(net.Conn)
			return writeAndRegUsage(conn, data)
		} else {
			newConnId, conn, err := sb.pickRandConn()
			if err != nil {
				return 0, errBrokenSwitchboard
			}
			*connId = newConnId
			return writeAndRegUsage(conn, data)
		}
	default:
		return 0, errors.New("unsupported traffic distribution strategy")
	}
}

// returns a random connId
func (sb *switchboard) pickRandConn() (uint32, net.Conn, error) {
	connCount := sb.connsCount()
	if atomic.LoadUint32(&sb.broken) == 1 || connCount == 0 {
		return 0, nil, errBrokenSwitchboard
	}

	// there is no guarantee that sb.conns still has the same amount of entries
	// between the count loop and the pick loop
	// so if the r > len(sb.conns) at the point of range call, the last visited element is picked
	var id uint32
	var conn net.Conn
	r := rand.Intn(connCount)
	var c int
	sb.conns.Range(func(connIdI, connI interface{}) bool {
		if r == c {
			id = connIdI.(uint32)
			conn = connI.(net.Conn)
			return false
		}
		c++
		return true
	})
	// if len(sb.conns) is 0
	if conn == nil {
		return 0, nil, errBrokenSwitchboard
	}
	return id, conn, nil
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
	sb.conns.Range(func(key, connI interface{}) bool {
		conn := connI.(net.Conn)
		conn.Close()
		sb.conns.Delete(key)
		return true
	})
}

// deplex function costantly reads from a TCP connection
func (sb *switchboard) deplex(connId uint32, conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, sb.session.ConnReceiveBufferSize)
	for {
		n, err := conn.Read(buf)
		sb.valve.rxWait(n)
		sb.valve.AddRx(int64(n))
		if err != nil {
			log.Debugf("a connection for session %v has closed: %v", sb.session.id, err)
			sb.conns.Delete(connId)
			atomic.AddUint32(&sb.numConns, ^uint32(0))
			sb.close("a connection has dropped unexpectedly")
			return
		}

		err = sb.session.recvDataFromRemote(buf[:n])
		if err != nil {
			log.Error(err)
		}
	}
}
