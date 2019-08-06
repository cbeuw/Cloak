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
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)

	run := func(obfuscator *Obfuscator, ct *testing.T) {
		obfsBuf := make([]byte, 512)
		f := &Frame{}
		_testFrame, _ := quick.Value(reflect.TypeOf(f), rand.New(rand.NewSource(42)))
		testFrame := _testFrame.Interface().(*Frame)
		i, err := obfuscator.Obfs(testFrame, obfsBuf)
		if err != nil {
			ct.Error("failed to obfs ", err)
		}

		resultFrame, err := obfuscator.Deobfs(obfsBuf[:i])
		if err != nil {
			ct.Error("failed to deobfs ", err)
		}
		if !bytes.Equal(testFrame.Payload, resultFrame.Payload) || testFrame.StreamID != resultFrame.StreamID {
			ct.Error("expecting", testFrame,
				"got", resultFrame)
		}
	}

	t.Run("plain", func(t *testing.T) {
		obfuscator, err := GenerateObfs(0x00, sessionKey)
		if err != nil {
			t.Errorf("failed to generate obfuscator %v", err)
		} else {
			run(obfuscator, t)
		}
	})
	t.Run("aes-gcm", func(t *testing.T) {
		obfuscator, err := GenerateObfs(0x01, sessionKey)
		if err != nil {
			t.Errorf("failed to generate obfuscator %v", err)
		} else {
			run(obfuscator, t)
		}
	})
	t.Run("chacha20-poly1305", func(t *testing.T) {
		obfuscator, err := GenerateObfs(0x02, sessionKey)
		if err != nil {
			t.Errorf("failed to generate obfuscator %v", err)
		} else {
			run(obfuscator, t)
		}
	})
	t.Run("unknown encryption method", func(t *testing.T) {
		_, err := GenerateObfs(0xff, sessionKey)
		if err == nil {
			t.Errorf("unknown encryption mehtod error expected")
		}
	})
	t.Run("bad key length", func(t *testing.T) {
		_, err := GenerateObfs(0xff, sessionKey[:31])
		if err == nil {
			t.Errorf("bad key length error expected")
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

	obfsBuf := make([]byte, 512)

	var key [32]byte
	rand.Read(key[:])
	b.Run("AES256GCM", func(b *testing.B) {
		c, _ := aes.NewCipher(key[:])
		payloadCipher, _ := cipher.NewGCM(c)

		obfs := MakeObfs(key, payloadCipher)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			obfs(testFrame, obfsBuf)
		}
	})
	b.Run("AES128GCM", func(b *testing.B) {
		c, _ := aes.NewCipher(key[:16])
		payloadCipher, _ := cipher.NewGCM(c)

		obfs := MakeObfs(key, payloadCipher)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			obfs(testFrame, obfsBuf)
		}
	})
	b.Run("plain", func(b *testing.B) {
		obfs := MakeObfs(key, nil)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			obfs(testFrame, obfsBuf)
		}
	})
	b.Run("chacha20Poly1305", func(b *testing.B) {
		payloadCipher, _ := chacha20poly1305.New(key[:16])

		obfs := MakeObfs(key, payloadCipher)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			obfs(testFrame, obfsBuf)
		}
	})
}
