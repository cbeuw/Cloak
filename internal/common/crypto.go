package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"time"

	log "github.com/sirupsen/logrus"
)

func AESGCMEncrypt(nonce []byte, key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Seal(nil, nonce, plaintext, nil), nil
}

func AESGCMDecrypt(nonce []byte, key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func CryptoRandRead(buf []byte) {
	RandRead(rand.Reader, buf)
}

func RandRead(randSource io.Reader, buf []byte) {
	_, err := randSource.Read(buf)
	if err == nil {
		return
	}
	waitDur := [10]time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 30 * time.Millisecond, 50 * time.Millisecond,
		100 * time.Millisecond, 300 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second,
		3 * time.Second, 5 * time.Second}
	for i := 0; i < 10; i++ {
		log.Errorf("Failed to get cryptographic random bytes: %v. Retrying...", err)
		_, err = rand.Read(buf)
		if err == nil {
			return
		}
		time.Sleep(time.Millisecond * waitDur[i])
	}
	log.Fatal("Cannot get cryptographic random bytes after 10 retries")
}
