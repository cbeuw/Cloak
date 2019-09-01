package multiplex

import (
	"bytes"
	"github.com/cbeuw/Cloak/internal/util"
	"math/rand"
	"testing"
)

var seshConfigOrdered = &SessionConfig{
	Obfuscator: nil,
	Valve:      nil,
	UnitRead:   util.ReadTLS,
}

var seshConfigUnordered = &SessionConfig{
	Obfuscator: nil,
	Valve:      nil,
	UnitRead:   util.ReadTLS,
	Unordered:  true,
}

func TestRecvDataFromRemote(t *testing.T) {
	testPayloadLen := 1024
	testPayload := make([]byte, testPayloadLen)
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
	t.Run("plain ordered", func(t *testing.T) {
		obfuscator, _ := GenerateObfs(E_METHOD_PLAIN, sessionKey, true)
		seshConfigOrdered.Obfuscator = obfuscator
		sesh := MakeSession(0, seshConfigOrdered)
		n, _ := sesh.Obfs(f, obfsBuf)

		sesh.recvDataFromRemote(obfsBuf[:n])
		stream, err := sesh.Accept()
		if err != nil {
			t.Error(err)
			return
		}

		resultPayload := make([]byte, testPayloadLen)
		_, err = stream.Read(resultPayload)
		if err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(testPayload, resultPayload) {
			t.Errorf("Expecting %x, got %x", testPayload, resultPayload)
		}
	})
	t.Run("aes-gcm ordered", func(t *testing.T) {
		obfuscator, _ := GenerateObfs(E_METHOD_AES_GCM, sessionKey, true)
		seshConfigOrdered.Obfuscator = obfuscator
		sesh := MakeSession(0, seshConfigOrdered)
		n, _ := sesh.Obfs(f, obfsBuf)

		sesh.recvDataFromRemote(obfsBuf[:n])
		stream, err := sesh.Accept()
		if err != nil {
			t.Error(err)
			return
		}

		resultPayload := make([]byte, testPayloadLen)
		_, err = stream.Read(resultPayload)
		if err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(testPayload, resultPayload) {
			t.Errorf("Expecting %x, got %x", testPayload, resultPayload)
		}
	})
	t.Run("chacha20-poly1305 ordered", func(t *testing.T) {
		obfuscator, _ := GenerateObfs(E_METHOD_CHACHA20_POLY1305, sessionKey, true)
		seshConfigOrdered.Obfuscator = obfuscator
		sesh := MakeSession(0, seshConfigOrdered)
		n, _ := sesh.Obfs(f, obfsBuf)

		sesh.recvDataFromRemote(obfsBuf[:n])
		stream, err := sesh.Accept()
		if err != nil {
			t.Error(err)
			return
		}

		resultPayload := make([]byte, testPayloadLen)
		_, err = stream.Read(resultPayload)
		if err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(testPayload, resultPayload) {
			t.Errorf("Expecting %x, got %x", testPayload, resultPayload)
		}
	})

	t.Run("plain unordered", func(t *testing.T) {
		obfuscator, _ := GenerateObfs(E_METHOD_PLAIN, sessionKey, true)
		seshConfigUnordered.Obfuscator = obfuscator
		sesh := MakeSession(0, seshConfigOrdered)
		n, _ := sesh.Obfs(f, obfsBuf)

		sesh.recvDataFromRemote(obfsBuf[:n])
		stream, err := sesh.Accept()
		if err != nil {
			t.Error(err)
			return
		}

		resultPayload := make([]byte, testPayloadLen)
		_, err = stream.Read(resultPayload)
		if err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(testPayload, resultPayload) {
			t.Errorf("Expecting %x, got %x", testPayload, resultPayload)
		}
	})

}

func BenchmarkRecvDataFromRemote_Ordered(b *testing.B) {
	testPayloadLen := 1024
	testPayload := make([]byte, testPayloadLen)
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
		obfuscator, _ := GenerateObfs(E_METHOD_PLAIN, sessionKey, true)
		seshConfigOrdered.Obfuscator = obfuscator
		sesh := MakeSession(0, seshConfigOrdered)
		n, _ := sesh.Obfs(f, obfsBuf)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sesh.recvDataFromRemote(obfsBuf[:n])
			b.SetBytes(int64(n))
		}
	})

	b.Run("aes-gcm", func(b *testing.B) {
		obfuscator, _ := GenerateObfs(E_METHOD_AES_GCM, sessionKey, true)
		seshConfigOrdered.Obfuscator = obfuscator
		sesh := MakeSession(0, seshConfigOrdered)
		n, _ := sesh.Obfs(f, obfsBuf)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sesh.recvDataFromRemote(obfsBuf[:n])
			b.SetBytes(int64(n))
		}
	})

	b.Run("chacha20-poly1305", func(b *testing.B) {
		obfuscator, _ := GenerateObfs(E_METHOD_CHACHA20_POLY1305, sessionKey, true)
		seshConfigOrdered.Obfuscator = obfuscator
		sesh := MakeSession(0, seshConfigOrdered)
		n, _ := sesh.Obfs(f, obfsBuf)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sesh.recvDataFromRemote(obfsBuf[:n])
			b.SetBytes(int64(n))
		}
	})

}
