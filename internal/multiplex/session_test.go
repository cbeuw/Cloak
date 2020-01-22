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

		err := sesh.recvDataFromRemote(obfsBuf[:n])
		if err != nil {
			t.Error(err)
			return
		}
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

		err := sesh.recvDataFromRemote(obfsBuf[:n])
		if err != nil {
			t.Error(err)
			return
		}
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

		err := sesh.recvDataFromRemote(obfsBuf[:n])
		if err != nil {
			t.Error(err)
			return
		}
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

		err := sesh.recvDataFromRemote(obfsBuf[:n])
		if err != nil {
			t.Error(err)
			return
		}
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

func TestRecvDataFromRemote_Closing_InOrder(t *testing.T) {
	testPayloadLen := 1024
	testPayload := make([]byte, testPayloadLen)
	rand.Read(testPayload)
	obfsBuf := make([]byte, 17000)

	sessionKey := make([]byte, 32)
	obfuscator, _ := GenerateObfs(E_METHOD_PLAIN, sessionKey, true)
	seshConfigOrdered.Obfuscator = obfuscator

	rand.Read(sessionKey)
	sesh := MakeSession(0, seshConfigOrdered)

	f1 := &Frame{
		1,
		0,
		C_NOOP,
		testPayload,
	}
	// create stream 1
	n, _ := sesh.Obfs(f1, obfsBuf)
	err := sesh.recvDataFromRemote(obfsBuf[:n])
	if err != nil {
		t.Fatalf("receiving normal frame for stream 1: %v", err)
	}
	s1I, ok := sesh.streams.Load(f1.StreamID)
	if !ok {
		t.Fatal("failed to fetch stream 1 after receiving it")
	}

	// create stream 2
	f2 := &Frame{
		2,
		0,
		C_NOOP,
		testPayload,
	}
	n, _ = sesh.Obfs(f2, obfsBuf)
	err = sesh.recvDataFromRemote(obfsBuf[:n])
	if err != nil {
		t.Fatalf("receiving normal frame for stream 2: %v", err)
	}
	s2I, ok := sesh.streams.Load(f2.StreamID)
	if !ok {
		t.Fatal("failed to fetch stream 2 after receiving it")
	}

	// close stream 1
	f1CloseStream := &Frame{
		1,
		1,
		C_STREAM,
		testPayload,
	}
	n, _ = sesh.Obfs(f1CloseStream, obfsBuf)
	err = sesh.recvDataFromRemote(obfsBuf[:n])
	if err != nil {
		t.Fatalf("receiving stream closing frame for stream 1: %v", err)
	}
	_, ok = sesh.streams.Load(f1.StreamID)
	if ok {
		t.Fatal("stream 1 still exist after receiving stream close")
	}
	s1 := s1I.(*Stream)
	if !s1.isClosed() {
		t.Fatal("stream 1 not marked as closed")
	}
	payloadBuf := make([]byte, testPayloadLen)
	_, err = s1.recvBuf.Read(payloadBuf)
	if err != nil || !bytes.Equal(payloadBuf, testPayload) {
		t.Fatalf("failed to read from stream 1 after closing: %v", err)
	}
	s2 := s2I.(*Stream)
	if s2.isClosed() {
		t.Fatal("stream 2 shouldn't be closed")
	}

	// close stream 1 again
	n, _ = sesh.Obfs(f1CloseStream, obfsBuf)
	err = sesh.recvDataFromRemote(obfsBuf[:n])
	if err != nil {
		t.Fatalf("receiving stream closing frame for stream 1: %v", err)
	}
	_, ok = sesh.streams.Load(f1.StreamID)
	if ok {
		t.Fatal("stream 1 exists after receiving stream close for the second time")
	}
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
			err := sesh.recvDataFromRemote(obfsBuf[:n])
			if err != nil {
				b.Error(err)
				return
			}
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
			err := sesh.recvDataFromRemote(obfsBuf[:n])
			if err != nil {
				b.Error(err)
				return
			}
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
			err := sesh.recvDataFromRemote(obfsBuf[:n])
			if err != nil {
				b.Error(err)
				return
			}
			b.SetBytes(int64(n))
		}
	})
}
