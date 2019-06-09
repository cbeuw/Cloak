package multiplex

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

type Crypto interface {
	encrypt([]byte) ([]byte, error)
	decrypt([]byte) ([]byte, error)
}

type Plain struct{}

func (p *Plain) encrypt(plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

func (p *Plain) decrypt(buf []byte) ([]byte, error) {
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

func (a *AES) encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, 12)
	rand.Read(nonce)
	aesgcm, err := cipher.NewGCM(a.cipher)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	ret := make([]byte, 12+len(plaintext)+16)
	copy(ret[:12], nonce)
	copy(ret[12:], ciphertext)
	return ret, nil
}

func (a *AES) decrypt(buf []byte) ([]byte, error) {
	aesgcm, err := cipher.NewGCM(a.cipher)
	if err != nil {
		return nil, err
	}
	plain, err := aesgcm.Open(nil, buf[:12], buf[12:], nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}
