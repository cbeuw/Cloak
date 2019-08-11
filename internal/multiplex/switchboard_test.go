package multiplex

import (
	"math/rand"
	"testing"
)

func BenchmarkSwitchboard_Send(b *testing.B) {
	seshConfig := &SessionConfig{
		Obfuscator: nil,
		Valve:      nil,
		UnitRead:   nil,
	}
	sesh := MakeSession(0, seshConfig)
	sb := makeSwitchboard(sesh, UNLIMITED_VALVE)
	hole := newBlackHole()
	sb.addConn(hole)
	connId, err := sb.assignRandomConn()
	if err != nil {
		b.Error("failed to get a random conn", err)
		return
	}
	data := make([]byte, 1000)
	rand.Read(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n, err := sb.send(data, &connId)
		if err != nil {
			b.Error(err)
			return
		}
		b.SetBytes(int64(n))
	}
}
