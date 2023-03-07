package multiplex

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cbeuw/connutil"
	"github.com/stretchr/testify/assert"
)

func TestSwitchboard_Send(t *testing.T) {
	doTest := func(seshConfig SessionConfig) {
		sesh := MakeSession(0, seshConfig)
		hole0 := connutil.Discard()
		sesh.sb.addConn(hole0)
		conn, err := sesh.sb.pickRandConn()
		if err != nil {
			t.Error("failed to get a random conn", err)
			return
		}
		data := make([]byte, 1000)
		rand.Read(data)
		_, err = sesh.sb.send(data, &conn)
		if err != nil {
			t.Error(err)
			return
		}

		hole1 := connutil.Discard()
		sesh.sb.addConn(hole1)
		conn, err = sesh.sb.pickRandConn()
		if err != nil {
			t.Error("failed to get a random conn", err)
			return
		}
		_, err = sesh.sb.send(data, &conn)
		if err != nil {
			t.Error(err)
			return
		}

		conn, err = sesh.sb.pickRandConn()
		if err != nil {
			t.Error("failed to get a random conn", err)
			return
		}
		_, err = sesh.sb.send(data, &conn)
		if err != nil {
			t.Error(err)
			return
		}
	}

	t.Run("Ordered", func(t *testing.T) {
		seshConfig := SessionConfig{
			Unordered: false,
		}
		doTest(seshConfig)
	})
	t.Run("Unordered", func(t *testing.T) {
		seshConfig := SessionConfig{
			Unordered: true,
		}
		doTest(seshConfig)
	})
}

func BenchmarkSwitchboard_Send(b *testing.B) {
	hole := connutil.Discard()
	seshConfig := SessionConfig{}
	sesh := MakeSession(0, seshConfig)
	sesh.sb.addConn(hole)
	conn, err := sesh.sb.pickRandConn()
	if err != nil {
		b.Error("failed to get a random conn", err)
		return
	}
	data := make([]byte, 1000)
	rand.Read(data)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sesh.sb.send(data, &conn)
	}
}

func TestSwitchboard_TxCredit(t *testing.T) {
	seshConfig := SessionConfig{
		Valve: MakeValve(1<<20, 1<<20),
	}
	sesh := MakeSession(0, seshConfig)
	hole := connutil.Discard()
	sesh.sb.addConn(hole)
	conn, err := sesh.sb.pickRandConn()
	if err != nil {
		t.Error("failed to get a random conn", err)
		return
	}
	data := make([]byte, 1000)
	rand.Read(data)

	t.Run("fixed conn mapping", func(t *testing.T) {
		*sesh.sb.valve.(*LimitedValve).tx = 0
		sesh.sb.strategy = fixedConnMapping
		n, err := sesh.sb.send(data[:10], &conn)
		if err != nil {
			t.Error(err)
			return
		}
		if n != 10 {
			t.Errorf("wanted to send %v, got %v", 10, n)
			return
		}
		if *sesh.sb.valve.(*LimitedValve).tx != 10 {
			t.Error("tx credit didn't increase by 10")
		}
	})
	t.Run("uniform spread", func(t *testing.T) {
		*sesh.sb.valve.(*LimitedValve).tx = 0
		sesh.sb.strategy = uniformSpread
		n, err := sesh.sb.send(data[:10], &conn)
		if err != nil {
			t.Error(err)
			return
		}
		if n != 10 {
			t.Errorf("wanted to send %v, got %v", 10, n)
			return
		}
		if *sesh.sb.valve.(*LimitedValve).tx != 10 {
			t.Error("tx credit didn't increase by 10")
		}
	})
}

func TestSwitchboard_CloseOnOneDisconn(t *testing.T) {
	var sessionKey [32]byte
	rand.Read(sessionKey[:])
	sesh := setupSesh(false, sessionKey, EncryptionMethodPlain)

	conn0client, conn0server := connutil.AsyncPipe()
	sesh.AddConnection(conn0client)

	conn1client, _ := connutil.AsyncPipe()
	sesh.AddConnection(conn1client)

	conn0server.Close()

	assert.Eventually(t, func() bool {
		return sesh.IsClosed()
	}, time.Second, 10*time.Millisecond, "session not closed after one conn is disconnected")

	if _, err := conn1client.Write([]byte{0x00}); err == nil {
		t.Error("the other conn is still connected")
		return
	}
}

func TestSwitchboard_ConnsCount(t *testing.T) {
	seshConfig := SessionConfig{
		Valve: MakeValve(1<<20, 1<<20),
	}
	sesh := MakeSession(0, seshConfig)

	var wg sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			sesh.AddConnection(connutil.Discard())
			wg.Done()
		}()
	}
	wg.Wait()

	if atomic.LoadUint32(&sesh.sb.connsCount) != 1000 {
		t.Error("connsCount incorrect")
	}

	sesh.sb.closeAll()

	assert.Eventuallyf(t, func() bool {
		return atomic.LoadUint32(&sesh.sb.connsCount) == 0
	}, time.Second, 10*time.Millisecond, "connsCount incorrect: %v", atomic.LoadUint32(&sesh.sb.connsCount))
}
