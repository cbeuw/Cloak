package common

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

const gcmTagSize = 16

func TestAESGCM(t *testing.T) {
	// test vectors from https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
	t.Run("correct 128", func(t *testing.T) {
		key, _ := hex.DecodeString("00000000000000000000000000000000")
		plaintext, _ := hex.DecodeString("")
		nonce, _ := hex.DecodeString("000000000000000000000000")
		ciphertext, _ := hex.DecodeString("")
		tag, _ := hex.DecodeString("58e2fccefa7e3061367f1d57a4e7455a")

		encryptedWithTag, err := AESGCMEncrypt(nonce, key, plaintext)
		assert.NoError(t, err)
		assert.Equal(t, ciphertext, encryptedWithTag[:len(plaintext)])
		assert.Equal(t, tag, encryptedWithTag[len(plaintext):len(plaintext)+gcmTagSize])

		decrypted, err := AESGCMDecrypt(nonce, key, encryptedWithTag)
		assert.NoError(t, err)
		// slight inconvenience here that assert.Equal does not consider a nil slice and an empty slice to be
		// equal. decrypted should be []byte(nil) but plaintext is []byte{}
		assert.True(t, bytes.Equal(plaintext, decrypted))
	})
	t.Run("bad key size", func(t *testing.T) {
		key, _ := hex.DecodeString("0000000000000000000000000000")
		plaintext, _ := hex.DecodeString("")
		nonce, _ := hex.DecodeString("000000000000000000000000")
		ciphertext, _ := hex.DecodeString("")
		tag, _ := hex.DecodeString("58e2fccefa7e3061367f1d57a4e7455a")

		_, err := AESGCMEncrypt(nonce, key, plaintext)
		assert.Error(t, err)

		_, err = AESGCMDecrypt(nonce, key, append(ciphertext, tag...))
		assert.Error(t, err)
	})
	t.Run("bad nonce size", func(t *testing.T) {
		key, _ := hex.DecodeString("00000000000000000000000000000000")
		plaintext, _ := hex.DecodeString("")
		nonce, _ := hex.DecodeString("00000000000000000000")
		ciphertext, _ := hex.DecodeString("")
		tag, _ := hex.DecodeString("58e2fccefa7e3061367f1d57a4e7455a")

		_, err := AESGCMEncrypt(nonce, key, plaintext)
		assert.Error(t, err)

		_, err = AESGCMDecrypt(nonce, key, append(ciphertext, tag...))
		assert.Error(t, err)
	})
	t.Run("bad tag", func(t *testing.T) {
		key, _ := hex.DecodeString("00000000000000000000000000000000")
		nonce, _ := hex.DecodeString("00000000000000000000")
		ciphertext, _ := hex.DecodeString("")
		tag, _ := hex.DecodeString("fffffccefa7e3061367f1d57a4e745ff")

		_, err := AESGCMDecrypt(nonce, key, append(ciphertext, tag...))
		assert.Error(t, err)
	})
}

type failingReader struct {
	fails  int
	reader io.Reader
}

func (f *failingReader) Read(p []byte) (n int, err error) {
	if f.fails > 0 {
		f.fails -= 1
		return 0, errors.New("no data for you yet")
	} else {
		return f.reader.Read(p)
	}
}

func TestRandRead(t *testing.T) {
	failer := &failingReader{
		fails:  3,
		reader: rand.New(rand.NewSource(0)),
	}
	readBuf := make([]byte, 10)
	RandRead(failer, readBuf)
	assert.NotEqual(t, [10]byte{}, readBuf)
}
