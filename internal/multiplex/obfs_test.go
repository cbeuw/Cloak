package multiplex

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"golang.org/x/crypto/chacha20poly1305"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

func TestGenerateObfs(t *testing.T) {
	var sessionKey [32]byte
	rand.Read(sessionKey[:])

	run := func(obfuscator Obfuscator, ct *testing.T) {
		obfsBuf := make([]byte, 512)
		_testFrame, _ := quick.Value(reflect.TypeOf(&Frame{}), rand.New(rand.NewSource(42)))
		testFrame := _testFrame.Interface().(*Frame)
		i, err := obfuscator.obfuscate(testFrame, obfsBuf, 0)
		if err != nil {
			ct.Error("failed to obfs ", err)
			return
		}

		var resultFrame Frame
		err = obfuscator.deobfuscate(&resultFrame, obfsBuf[:i])
		if err != nil {
			ct.Error("failed to deobfs ", err)
			return
		}
		if !bytes.Equal(testFrame.Payload, resultFrame.Payload) || testFrame.StreamID != resultFrame.StreamID {
			ct.Error("expecting", testFrame,
				"got", resultFrame)
			return
		}
	}

	t.Run("plain", func(t *testing.T) {
		obfuscator, err := MakeObfuscator(EncryptionMethodPlain, sessionKey)
		if err != nil {
			t.Errorf("failed to generate obfuscator %v", err)
		} else {
			run(obfuscator, t)
		}
	})
	t.Run("aes-256-gcm", func(t *testing.T) {
		obfuscator, err := MakeObfuscator(EncryptionMethodAES256GCM, sessionKey)
		if err != nil {
			t.Errorf("failed to generate obfuscator %v", err)
		} else {
			run(obfuscator, t)
		}
	})
	t.Run("aes-128-gcm", func(t *testing.T) {
		obfuscator, err := MakeObfuscator(EncryptionMethodAES128GCM, sessionKey)
		if err != nil {
			t.Errorf("failed to generate obfuscator %v", err)
		} else {
			run(obfuscator, t)
		}
	})
	t.Run("chacha20-poly1305", func(t *testing.T) {
		obfuscator, err := MakeObfuscator(EncryptionMethodChaha20Poly1305, sessionKey)
		if err != nil {
			t.Errorf("failed to generate obfuscator %v", err)
		} else {
			run(obfuscator, t)
		}
	})
	t.Run("unknown encryption method", func(t *testing.T) {
		_, err := MakeObfuscator(0xff, sessionKey)
		if err == nil {
			t.Errorf("unknown encryption mehtod error expected")
		}
	})
}

func BenchmarkObfs(b *testing.B) {
	testPayload := make([]byte, 1024)
	rand.Read(testPayload)
	testFrame := &Frame{
		1,
		0,
		0,
		testPayload,
	}

	obfsBuf := make([]byte, defaultSendRecvBufSize)

	var key [32]byte
	rand.Read(key[:])
	b.Run("AES256GCM", func(b *testing.B) {
		c, _ := aes.NewCipher(key[:])
		payloadCipher, _ := cipher.NewGCM(c)

		obfuscator := Obfuscator{
			payloadCipher: payloadCipher,
			SessionKey:    key,
			maxOverhead:   payloadCipher.Overhead(),
		}

		b.SetBytes(int64(len(testFrame.Payload)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			obfuscator.obfuscate(testFrame, obfsBuf, 0)
		}
	})
	b.Run("AES128GCM", func(b *testing.B) {
		c, _ := aes.NewCipher(key[:16])
		payloadCipher, _ := cipher.NewGCM(c)

		obfuscator := Obfuscator{
			payloadCipher: payloadCipher,
			SessionKey:    key,
			maxOverhead:   payloadCipher.Overhead(),
		}
		b.SetBytes(int64(len(testFrame.Payload)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			obfuscator.obfuscate(testFrame, obfsBuf, 0)
		}
	})
	b.Run("plain", func(b *testing.B) {
		obfuscator := Obfuscator{
			payloadCipher: nil,
			SessionKey:    key,
			maxOverhead:   salsa20NonceSize,
		}
		b.SetBytes(int64(len(testFrame.Payload)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			obfuscator.obfuscate(testFrame, obfsBuf, 0)
		}
	})
	b.Run("chacha20Poly1305", func(b *testing.B) {
		payloadCipher, _ := chacha20poly1305.New(key[:])

		obfuscator := Obfuscator{
			payloadCipher: payloadCipher,
			SessionKey:    key,
			maxOverhead:   payloadCipher.Overhead(),
		}
		b.SetBytes(int64(len(testFrame.Payload)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			obfuscator.obfuscate(testFrame, obfsBuf, 0)
		}
	})
}

func BenchmarkDeobfs(b *testing.B) {
	testPayload := make([]byte, 1024)
	rand.Read(testPayload)
	testFrame := &Frame{
		1,
		0,
		0,
		testPayload,
	}

	obfsBuf := make([]byte, defaultSendRecvBufSize)

	var key [32]byte
	rand.Read(key[:])
	b.Run("AES256GCM", func(b *testing.B) {
		c, _ := aes.NewCipher(key[:])
		payloadCipher, _ := cipher.NewGCM(c)
		obfuscator := Obfuscator{
			payloadCipher: payloadCipher,
			SessionKey:    key,
			maxOverhead:   payloadCipher.Overhead(),
		}

		n, _ := obfuscator.obfuscate(testFrame, obfsBuf, 0)

		frame := new(Frame)
		b.SetBytes(int64(n))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			obfuscator.deobfuscate(frame, obfsBuf[:n])
		}
	})
	b.Run("AES128GCM", func(b *testing.B) {
		c, _ := aes.NewCipher(key[:16])
		payloadCipher, _ := cipher.NewGCM(c)

		obfuscator := Obfuscator{
			payloadCipher: payloadCipher,
			SessionKey:    key,
			maxOverhead:   payloadCipher.Overhead(),
		}
		n, _ := obfuscator.obfuscate(testFrame, obfsBuf, 0)

		frame := new(Frame)
		b.ResetTimer()
		b.SetBytes(int64(n))
		for i := 0; i < b.N; i++ {
			obfuscator.deobfuscate(frame, obfsBuf[:n])
		}
	})
	b.Run("plain", func(b *testing.B) {
		obfuscator := Obfuscator{
			payloadCipher: nil,
			SessionKey:    key,
			maxOverhead:   salsa20NonceSize,
		}
		n, _ := obfuscator.obfuscate(testFrame, obfsBuf, 0)

		frame := new(Frame)
		b.ResetTimer()
		b.SetBytes(int64(n))
		for i := 0; i < b.N; i++ {
			obfuscator.deobfuscate(frame, obfsBuf[:n])
		}
	})
	b.Run("chacha20Poly1305", func(b *testing.B) {
		payloadCipher, _ := chacha20poly1305.New(key[:])

		obfuscator := Obfuscator{
			payloadCipher: nil,
			SessionKey:    key,
			maxOverhead:   payloadCipher.Overhead(),
		}

		n, _ := obfuscator.obfuscate(testFrame, obfsBuf, 0)

		frame := new(Frame)
		b.ResetTimer()
		b.SetBytes(int64(n))
		for i := 0; i < b.N; i++ {
			obfuscator.deobfuscate(frame, obfsBuf[:n])
		}
	})
}
