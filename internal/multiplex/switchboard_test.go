package multiplex

import (
	"github.com/cbeuw/Cloak/internal/util"
	"math/rand"
	"net"
	"testing"
	"time"
)

func TestSwitchboard_Send(t *testing.T) {
	getHole := func() net.Conn {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		go func() {
			net.Dial("tcp", l.Addr().String())
		}()
		hole, _ := l.Accept()
		return hole
	}
	doTest := func(seshConfig *SessionConfig) {
		sesh := MakeSession(0, seshConfig)
		hole0 := getHole()
		sesh.sb.addConn(hole0)
		connId, _, err := sesh.sb.pickRandConn()
		if err != nil {
			t.Error("failed to get a random conn", err)
			return
		}
		data := make([]byte, 1000)
		rand.Read(data)
		_, err = sesh.sb.send(data, &connId)
		if err != nil {
			t.Error(err)
			return
		}

		hole1 := getHole()
		sesh.sb.addConn(hole1)
		connId, _, err = sesh.sb.pickRandConn()
		if err != nil {
			t.Error("failed to get a random conn", err)
			return
		}
		_, err = sesh.sb.send(data, &connId)
		if err != nil {
			t.Error(err)
			return
		}

		connId, _, err = sesh.sb.pickRandConn()
		if err != nil {
			t.Error("failed to get a random conn", err)
			return
		}
		_, err = sesh.sb.send(data, &connId)
		if err != nil {
			t.Error(err)
			return
		}
	}

	t.Run("Ordered", func(t *testing.T) {
		seshConfig := &SessionConfig{
			Obfuscator: nil,
			Valve:      nil,
			UnitRead:   util.ReadTLS,
			Unordered:  false,
		}
		doTest(seshConfig)
	})
	t.Run("Unordered", func(t *testing.T) {
		seshConfig := &SessionConfig{
			Obfuscator: nil,
			Valve:      nil,
			UnitRead:   util.ReadTLS,
			Unordered:  true,
		}
		doTest(seshConfig)
	})
}

func BenchmarkSwitchboard_Send(b *testing.B) {
	hole := newBlackHole()
	seshConfig := &SessionConfig{
		Obfuscator: nil,
		Valve:      nil,
		UnitRead:   util.ReadTLS,
	}
	sesh := MakeSession(0, seshConfig)
	sesh.sb.addConn(hole)
	connId, _, err := sesh.sb.pickRandConn()
	if err != nil {
		b.Error("failed to get a random conn", err)
		return
	}
	data := make([]byte, 1000)
	rand.Read(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n, err := sesh.sb.send(data, &connId)
		if err != nil {
			b.Error(err)
			return
		}
		b.SetBytes(int64(n))
	}
}

func TestSwitchboard_TxCredit(t *testing.T) {
	seshConfig := &SessionConfig{
		Obfuscator: nil,
		Valve:      MakeValve(1<<20, 1<<20),
		UnitRead:   util.ReadTLS,
	}
	sesh := MakeSession(0, seshConfig)
	hole := newBlackHole()
	sesh.sb.addConn(hole)
	connId, _, err := sesh.sb.pickRandConn()
	if err != nil {
		t.Error("failed to get a random conn", err)
		return
	}
	data := make([]byte, 1000)
	rand.Read(data)

	t.Run("FIXED CONN MAPPING", func(t *testing.T) {
		*sesh.sb.Valve.(*LimitedValve).tx = 0
		sesh.sb.strategy = FIXED_CONN_MAPPING
		n, err := sesh.sb.send(data[:10], &connId)
		if err != nil {
			t.Error(err)
			return
		}
		if n != 10 {
			t.Errorf("wanted to send %v, got %v", 10, n)
			return
		}
		if *sesh.sb.Valve.(*LimitedValve).tx != 10 {
			t.Error("tx credit didn't increase by 10")
		}
	})
	t.Run("UNIFORM", func(t *testing.T) {
		*sesh.sb.Valve.(*LimitedValve).tx = 0
		sesh.sb.strategy = UNIFORM_SPREAD
		n, err := sesh.sb.send(data[:10], &connId)
		if err != nil {
			t.Error(err)
			return
		}
		if n != 10 {
			t.Errorf("wanted to send %v, got %v", 10, n)
			return
		}
		if *sesh.sb.Valve.(*LimitedValve).tx != 10 {
			t.Error("tx credit didn't increase by 10")
		}
	})
}

func TestSwitchboard_CloseOnOneDisconn(t *testing.T) {
	sesh := setupSesh(false)

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addRemoteConn := func(close chan struct{}) {
		conn, _ := net.Dial("tcp", l.Addr().String())
		for {
			conn.Write([]byte{0x00})
			<-close
			conn.Close()
		}
	}

	close0 := make(chan struct{})
	go addRemoteConn(close0)
	conn0, _ := l.Accept()
	sesh.AddConnection(conn0)

	close1 := make(chan struct{})
	go addRemoteConn(close1)
	conn1, _ := l.Accept()
	sesh.AddConnection(conn1)

	close0 <- struct{}{}

	time.Sleep(100 * time.Millisecond)

	if !sesh.IsClosed() {
		t.Error("session not closed after one conn is disconnected")
		return
	}
	if _, err := conn1.Write([]byte{0x00}); err == nil {
		t.Error("the other conn is still connected")
		return
	}
}
