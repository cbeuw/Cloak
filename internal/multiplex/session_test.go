package multiplex

import (
	"github.com/cbeuw/Cloak/internal/util"
	"math/rand"
	"testing"
)

var seshConfig = &SessionConfig{
	Obfuscator: nil,
	Valve:      nil,
	UnitRead:   util.ReadTLS,
}

func BenchmarkRecvDataFromRemote(b *testing.B) {
	testPayload := make([]byte, 1024)
	rand.Read(testPayload)
	f := &Frame{
		1,
		0,
		0,
		testPayload,
	}
	obfsBuf := make([]byte, 17000)

	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)

	b.Run("plain", func(b *testing.B) {
		obfuscator, _ := GenerateObfs(0x00, sessionKey)
		seshConfig.Obfuscator = obfuscator
		sesh := MakeSession(0, seshConfig)
		n, _ := sesh.Obfs(f, obfsBuf)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sesh.recvDataFromRemote(obfsBuf[:n])
			b.SetBytes(int64(n))
		}
	})

	b.Run("aes-gcm", func(b *testing.B) {
		obfuscator, _ := GenerateObfs(0x01, sessionKey)
		seshConfig.Obfuscator = obfuscator
		sesh := MakeSession(0, seshConfig)
		n, _ := sesh.Obfs(f, obfsBuf)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sesh.recvDataFromRemote(obfsBuf[:n])
			b.SetBytes(int64(n))
		}
	})

	b.Run("chacha20-poly1305", func(b *testing.B) {
		obfuscator, _ := GenerateObfs(0x02, sessionKey)
		seshConfig.Obfuscator = obfuscator
		sesh := MakeSession(0, seshConfig)
		n, _ := sesh.Obfs(f, obfsBuf)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sesh.recvDataFromRemote(obfsBuf[:n])
			b.SetBytes(int64(n))
		}
	})

}
