package multiplex

import (
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestGenerateObfs(t *testing.T) {
	var sessionKey [32]byte
	rand.Read(sessionKey[:])

	run := func(o Obfuscator, t *testing.T) {
		obfsBuf := make([]byte, 512)
		_testFrame, _ := quick.Value(reflect.TypeOf(Frame{}), rand.New(rand.NewSource(42)))
		testFrame := _testFrame.Interface().(Frame)
		i, err := o.obfuscate(&testFrame, obfsBuf, 0)
		assert.NoError(t, err)
		var resultFrame Frame

		err = o.deobfuscate(&resultFrame, obfsBuf[:i])
		assert.NoError(t, err)
		assert.EqualValues(t, testFrame, resultFrame)
	}

	t.Run("plain", func(t *testing.T) {
		o, err := MakeObfuscator(EncryptionMethodPlain, sessionKey)
		assert.NoError(t, err)
		run(o, t)
	})
	t.Run("aes-256-gcm", func(t *testing.T) {
		o, err := MakeObfuscator(EncryptionMethodAES256GCM, sessionKey)
		assert.NoError(t, err)
		run(o, t)
	})
	t.Run("aes-128-gcm", func(t *testing.T) {
		o, err := MakeObfuscator(EncryptionMethodAES128GCM, sessionKey)
		assert.NoError(t, err)
		run(o, t)
	})
	t.Run("chacha20-poly1305", func(t *testing.T) {
		o, err := MakeObfuscator(EncryptionMethodChaha20Poly1305, sessionKey)
		assert.NoError(t, err)
		run(o, t)
	})
	t.Run("unknown encryption method", func(t *testing.T) {
		_, err := MakeObfuscator(0xff, sessionKey)
		assert.Error(t, err)
	})
}

func TestObfuscate(t *testing.T) {
	var sessionKey [32]byte
	rand.Read(sessionKey[:])

	const testPayloadLen = 1024
	testPayload := make([]byte, testPayloadLen)
	rand.Read(testPayload)
	f := Frame{
		StreamID: 0,
		Seq:      0,
		Closing:  0,
		Payload:  testPayload,
	}

	runTest := func(t *testing.T, o Obfuscator) {
		obfsBuf := make([]byte, testPayloadLen*2)
		n, err := o.obfuscate(&f, obfsBuf, 0)
		assert.NoError(t, err)

		resultFrame := Frame{}
		err = o.deobfuscate(&resultFrame, obfsBuf[:n])
		assert.NoError(t, err)

		assert.EqualValues(t, f, resultFrame)
	}

	t.Run("plain", func(t *testing.T) {
		o := Obfuscator{
			payloadCipher: nil,
			sessionKey:    sessionKey,
		}
		runTest(t, o)
	})

	t.Run("aes-128-gcm", func(t *testing.T) {
		c, err := aes.NewCipher(sessionKey[:16])
		assert.NoError(t, err)
		payloadCipher, err := cipher.NewGCM(c)
		assert.NoError(t, err)
		o := Obfuscator{
			payloadCipher: payloadCipher,
			sessionKey:    sessionKey,
		}
		runTest(t, o)
	})

	t.Run("aes-256-gcm", func(t *testing.T) {
		c, err := aes.NewCipher(sessionKey[:])
		assert.NoError(t, err)
		payloadCipher, err := cipher.NewGCM(c)
		assert.NoError(t, err)
		o := Obfuscator{
			payloadCipher: payloadCipher,
			sessionKey:    sessionKey,
		}
		runTest(t, o)
	})

	t.Run("chacha20-poly1305", func(t *testing.T) {
		payloadCipher, err := chacha20poly1305.New(sessionKey[:])
		assert.NoError(t, err)
		o := Obfuscator{
			payloadCipher: payloadCipher,
			sessionKey:    sessionKey,
		}
		runTest(t, o)
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

	obfsBuf := make([]byte, len(testPayload)*2)

	var key [32]byte
	rand.Read(key[:])
	b.Run("AES256GCM", func(b *testing.B) {
		c, _ := aes.NewCipher(key[:])
		payloadCipher, _ := cipher.NewGCM(c)

		obfuscator := Obfuscator{
			payloadCipher: payloadCipher,
			sessionKey:    key,
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
			sessionKey:    key,
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
			sessionKey:    key,
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
			sessionKey:    key,
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

	obfsBuf := make([]byte, len(testPayload)*2)

	var key [32]byte
	rand.Read(key[:])
	b.Run("AES256GCM", func(b *testing.B) {
		c, _ := aes.NewCipher(key[:])
		payloadCipher, _ := cipher.NewGCM(c)
		obfuscator := Obfuscator{
			payloadCipher: payloadCipher,
			sessionKey:    key,
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
			sessionKey:    key,
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
			sessionKey:    key,
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
			payloadCipher: payloadCipher,
			sessionKey:    key,
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
