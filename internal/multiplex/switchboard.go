package multiplex

import (
	"errors"
	"github.com/cbeuw/Cloak/internal/common"
	log "github.com/sirupsen/logrus"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
)

type switchboardStrategy int

const (
	fixedConnMapping switchboardStrategy = iota
	uniformSpread
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

	conns      sync.Map
	connsCount uint32
	randPool   sync.Pool

	broken uint32
}

func makeSwitchboard(sesh *Session) *switchboard {
	sb := &switchboard{
		session:  sesh,
		strategy: uniformSpread,
		valve:    sesh.Valve,
		randPool: sync.Pool{New: func() interface{} {
			var state [32]byte
			common.CryptoRandRead(state[:])
			return rand.New(rand.NewChaCha8(state))
		}},
	}
	return sb
}

var errBrokenSwitchboard = errors.New("the switchboard is broken")

func (sb *switchboard) addConn(conn net.Conn) {
	connId := atomic.AddUint32(&sb.connsCount, 1) - 1
	sb.conns.Store(connId, conn)
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
	case uniformSpread:
		conn, err = sb.pickRandConn()
		if err != nil {
			return 0, errBrokenSwitchboard
		}
		n, err = conn.Write(data)
		if err != nil {
			sb.session.SetTerminalMsg("failed to send to remote " + err.Error())
			sb.session.passiveClose()
			return n, err
		}
	case fixedConnMapping:
		// FIXME: this strategy has a tendency to cause a TLS conn socket buffer to fill up,
		// which is a problem when multiple streams are mapped to the same conn, resulting
		// in all such streams being blocked.
		conn = *assignedConn
		if conn == nil {
			conn, err = sb.pickRandConn()
			if err != nil {
				sb.session.SetTerminalMsg("failed to pick a connection " + err.Error())
				sb.session.passiveClose()
				return 0, err
			}
			*assignedConn = conn
		}
		n, err = conn.Write(data)
		if err != nil {
			sb.session.SetTerminalMsg("failed to send to remote " + err.Error())
			sb.session.passiveClose()
			return n, err
		}
	default:
		return 0, errors.New("unsupported traffic distribution strategy")
	}

	sb.valve.AddTx(int64(n))
	return n, nil
}

// returns a random conn. This function can be called concurrently.
func (sb *switchboard) pickRandConn() (net.Conn, error) {
	if atomic.LoadUint32(&sb.broken) == 1 {
		return nil, errBrokenSwitchboard
	}

	connsCount := atomic.LoadUint32(&sb.connsCount)
	if connsCount == 0 {
		return nil, errBrokenSwitchboard
	}

	randReader := sb.randPool.Get().(*rand.Rand)
	connId := randReader.Uint32N(connsCount)
	sb.randPool.Put(randReader)

	ret, ok := sb.conns.Load(connId)
	if !ok {
		log.Errorf("failed to get conn %d", connId)
		return nil, errBrokenSwitchboard
	}
	return ret.(net.Conn), nil
}

// actively triggered by session.Close()
func (sb *switchboard) closeAll() {
	if !atomic.CompareAndSwapUint32(&sb.broken, 0, 1) {
		return
	}
	atomic.StoreUint32(&sb.connsCount, 0)
	sb.conns.Range(func(_, conn interface{}) bool {
		conn.(net.Conn).Close()
		sb.conns.Delete(conn)
		return true
	})
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
