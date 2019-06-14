package multiplex

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"golang.org/x/crypto/chacha20poly1305"
)

type Crypto interface {
	encrypt([]byte, []byte) ([]byte, error)
	decrypt([]byte, []byte) ([]byte, error)
}

type Plain struct{}

func (p *Plain) encrypt(plaintext []byte, nonce []byte) ([]byte, error) {
	salt := make([]byte, 16)
	rand.Read(salt)
	return append(plaintext, salt...), nil
}

func (p *Plain) decrypt(buf []byte, nonce []byte) ([]byte, error) {
	return buf, nil
}

type AES struct {
	cipher cipher.Block
}

func MakeAESCipher(key []byte) (*AES, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ret := AES{
		c,
	}
	return &ret, nil
}

func (a *AES) encrypt(plaintext []byte, nonce []byte) ([]byte, error) {
	aesgcm, err := cipher.NewGCM(a.cipher)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	ret := make([]byte, len(plaintext)+16)
	copy(ret, ciphertext)
	return ret, nil
}

func (a *AES) decrypt(ciphertext []byte, nonce []byte) ([]byte, error) {
	aesgcm, err := cipher.NewGCM(a.cipher)
	if err != nil {
		return nil, err
	}
	plain, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

type C20P1305 struct {
	cipher cipher.AEAD
}

func MakeCPCipher(key []byte) (*C20P1305, error) {
	c, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	ret := C20P1305{
		c,
	}
	return &ret, nil
}

func (c *C20P1305) encrypt(plaintext []byte, nonce []byte) ([]byte, error) {
	ciphertext := c.cipher.Seal(nil, nonce, plaintext, nil)
	ret := make([]byte, len(plaintext)+16)
	copy(ret, ciphertext)
	return ret, nil
}

func (c *C20P1305) decrypt(ciphertext []byte, nonce []byte) ([]byte, error) {
	plain, err := c.cipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}
