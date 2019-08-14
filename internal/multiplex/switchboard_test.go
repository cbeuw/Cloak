package multiplex

import (
	"github.com/cbeuw/Cloak/internal/util"
	"math/rand"
	"testing"
)

func BenchmarkSwitchboard_Send(b *testing.B) {
	seshConfig := &SessionConfig{
		Obfuscator: nil,
		Valve:      nil,
		UnitRead:   util.ReadTLS,
	}
	sesh := MakeSession(0, seshConfig)

	hole := newBlackHole()
	sesh.sb.addConn(hole)
	connId, err := sesh.sb.assignRandomConn()
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
	connId, err := sesh.sb.assignRandomConn()
	if err != nil {
		t.Error("failed to get a random conn", err)
		return
	}
	data := make([]byte, 1000)
	rand.Read(data)

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
}
