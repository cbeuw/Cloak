package multiplex

import (
	"github.com/cbeuw/Cloak/internal/util"
	"math/rand"
	"testing"
)

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
		sesh := MakeSession(0, UNLIMITED_VALVE, obfuscator, util.ReadTLS)
		n, _ := sesh.Obfs(f, obfsBuf)

		originalHeader := make([]byte, 12)
		copy(originalHeader, obfsBuf[5:17])

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sesh.recvDataFromRemote(obfsBuf[:n])
			b.SetBytes(int64(n))
			copy(obfsBuf[5:17], originalHeader)
		}
	})

	b.Run("aes-gcm", func(b *testing.B) {
		obfuscator, _ := GenerateObfs(0x01, sessionKey)
		sesh := MakeSession(0, UNLIMITED_VALVE, obfuscator, util.ReadTLS)
		n, _ := sesh.Obfs(f, obfsBuf)

		// because deobfs decrypts the header in-place, which alters the input
		originalHeader := make([]byte, 12)
		copy(originalHeader, obfsBuf[5:17])

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sesh.recvDataFromRemote(obfsBuf[:n])
			b.SetBytes(int64(n))
			copy(obfsBuf[5:17], originalHeader)
		}
	})

	b.Run("chacha20-poly1305", func(b *testing.B) {
		obfuscator, _ := GenerateObfs(0x02, sessionKey)
		sesh := MakeSession(0, UNLIMITED_VALVE, obfuscator, util.ReadTLS)
		n, _ := sesh.Obfs(f, obfsBuf)

		originalHeader := make([]byte, 12)
		copy(originalHeader, obfsBuf[5:17])

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sesh.recvDataFromRemote(obfsBuf[:n])
			b.SetBytes(int64(n))
			copy(obfsBuf[5:17], originalHeader)
		}
	})

}
