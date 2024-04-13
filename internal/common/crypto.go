package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
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
	if len(nonce) != aesgcm.NonceSize() {
		// check here so it doesn't panic
		return nil, errors.New("incorrect nonce size")
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
	if len(nonce) != aesgcm.NonceSize() {
		// check here so it doesn't panic
		return nil, errors.New("incorrect nonce size")
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

func backoff(f func() error) {
	err := f()
	if err == nil {
		return
	}
	waitDur := [10]time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 30 * time.Millisecond, 50 * time.Millisecond,
		100 * time.Millisecond, 300 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second,
		3 * time.Second, 5 * time.Second}
	for i := 0; i < 10; i++ {
		log.Errorf("Failed to get random: %v. Retrying...", err)
		err = f()
		if err == nil {
			return
		}
		time.Sleep(waitDur[i])
	}
	log.Fatal("Cannot get random after 10 retries")
}

func RandRead(randSource io.Reader, buf []byte) {
	backoff(func() error {
		_, err := randSource.Read(buf)
		return err
	})
}

func RandItem[T any](list []T) T {
	return list[RandInt(len(list))]
}

func RandInt(n int) int {
	s := new(int)
	backoff(func() error {
		size, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
		if err != nil {
			return err
		}
		*s = int(size.Int64())
		return nil
	})
	return *s
}
