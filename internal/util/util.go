package util

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

/*
func Pipe(dst net.Conn, src net.Conn, srcReadTimeout time.Duration) {
	// The maximum size of TLS message will be 16380+14+16. 14 because of the stream header and 16
	// because of the salt/mac
	// 16408 is the max TLS message size on Firefox
	buf := make([]byte, 16378)
	for {
		if srcReadTimeout != 0 {
			src.SetReadDeadline(time.Now().Add(srcReadTimeout))
		}
		i, err := io.ReadAtLeast(src, buf, 1)
		if err != nil {
			dst.Close()
			src.Close()
			return
		}
		_, err = dst.Write(buf[:i])
		if err != nil {
			dst.Close()
			src.Close()
			return
		}
	}
}

*/
