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

	run := func(obfuscator *Obfuscator, ct *testing.T) {
		obfsBuf := make([]byte, 512)
		f := &Frame{}
		_testFrame, _ := quick.Value(reflect.TypeOf(f), rand.New(rand.NewSource(42)))
		testFrame := _testFrame.Interface().(*Frame)
		i, err := obfuscator.Obfs(testFrame, obfsBuf)
		if err != nil {
			ct.Error("failed to obfs ", err)
			return
		}

		resultFrame, err := obfuscator.Deobfs(obfsBuf[:i])
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
		obfuscator, err := MakeObfuscator(E_METHOD_PLAIN, sessionKey)
		if err != nil {
			t.Errorf("failed to generate obfuscator %v", err)
		} else {
			run(obfuscator, t)
		}
	})
	t.Run("plain no record layer", func(t *testing.T) {
		obfuscator, err := MakeObfuscator(E_METHOD_PLAIN, sessionKey)
		if err != nil {
			t.Errorf("failed to generate obfuscator %v", err)
		} else {
			run(obfuscator, t)
		}
	})
	t.Run("aes-gcm", func(t *testing.T) {
		obfuscator, err := MakeObfuscator(E_METHOD_AES_GCM, sessionKey)
		if err != nil {
			t.Errorf("failed to generate obfuscator %v", err)
		} else {
			run(obfuscator, t)
		}
	})
	t.Run("aes-gcm no record layer", func(t *testing.T) {
		obfuscator, err := MakeObfuscator(E_METHOD_AES_GCM, sessionKey)
		if err != nil {
			t.Errorf("failed to generate obfuscator %v", err)
		} else {
			run(obfuscator, t)
		}
	})
	t.Run("chacha20-poly1305", func(t *testing.T) {
		obfuscator, err := MakeObfuscator(E_METHOD_CHACHA20_POLY1305, sessionKey)
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

	obfsBuf := make([]byte, 2048)

	var key [32]byte
	rand.Read(key[:])
	b.Run("AES256GCM", func(b *testing.B) {
		c, _ := aes.NewCipher(key[:])
		payloadCipher, _ := cipher.NewGCM(c)

		obfs := MakeObfs(key, payloadCipher)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			n, err := obfs(testFrame, obfsBuf)
			if err != nil {
				b.Error(err)
				return
			}
			b.SetBytes(int64(n))
		}
	})
	b.Run("AES128GCM", func(b *testing.B) {
		c, _ := aes.NewCipher(key[:16])
		payloadCipher, _ := cipher.NewGCM(c)

		obfs := MakeObfs(key, payloadCipher)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			n, err := obfs(testFrame, obfsBuf)
			if err != nil {
				b.Error(err)
				return
			}
			b.SetBytes(int64(n))
		}
	})
	b.Run("plain", func(b *testing.B) {
		obfs := MakeObfs(key, nil)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			n, err := obfs(testFrame, obfsBuf)
			if err != nil {
				b.Error(err)
				return
			}
			b.SetBytes(int64(n))
		}
	})
	b.Run("chacha20Poly1305", func(b *testing.B) {
		payloadCipher, _ := chacha20poly1305.New(key[:16])

		obfs := MakeObfs(key, payloadCipher)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			n, err := obfs(testFrame, obfsBuf)
			if err != nil {
				b.Error(err)
				return
			}
			b.SetBytes(int64(n))
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

	obfsBuf := make([]byte, 2048)

	var key [32]byte
	rand.Read(key[:])
	b.Run("AES256GCM", func(b *testing.B) {
		c, _ := aes.NewCipher(key[:])
		payloadCipher, _ := cipher.NewGCM(c)

		obfs := MakeObfs(key, payloadCipher)
		n, _ := obfs(testFrame, obfsBuf)
		deobfs := MakeDeobfs(key, payloadCipher)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := deobfs(obfsBuf[:n])
			if err != nil {
				b.Error(err)
				return
			}
			b.SetBytes(int64(n))
		}
	})
	b.Run("AES128GCM", func(b *testing.B) {
		c, _ := aes.NewCipher(key[:16])
		payloadCipher, _ := cipher.NewGCM(c)

		obfs := MakeObfs(key, payloadCipher)
		n, _ := obfs(testFrame, obfsBuf)
		deobfs := MakeDeobfs(key, payloadCipher)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := deobfs(obfsBuf[:n])
			if err != nil {
				b.Error(err)
				return
			}
			b.SetBytes(int64(n))
		}
	})
	b.Run("plain", func(b *testing.B) {
		obfs := MakeObfs(key, nil)
		n, _ := obfs(testFrame, obfsBuf)
		deobfs := MakeDeobfs(key, nil)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := deobfs(obfsBuf[:n])
			if err != nil {
				b.Error(err)
				return
			}
			b.SetBytes(int64(n))
		}
	})
	b.Run("chacha20Poly1305", func(b *testing.B) {
		payloadCipher, _ := chacha20poly1305.New(key[:16])

		obfs := MakeObfs(key, payloadCipher)
		n, _ := obfs(testFrame, obfsBuf)
		deobfs := MakeDeobfs(key, payloadCipher)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := deobfs(obfsBuf[:n])
			if err != nil {
				b.Error(err)
				return
			}
			b.SetBytes(int64(n))
		}
	})
}
