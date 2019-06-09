package multiplex

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

type Crypto interface {
	encrypt([]byte) []byte
	decrypt([]byte) []byte
}

type Plain struct{}

func (p *Plain) encrypt(plaintext []byte) []byte {
	return plaintext
}

func (p *Plain) decrypt(buf []byte) []byte {
	return buf
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

func (a *AES) encrypt(plaintext []byte) []byte {
	iv := make([]byte, 16)
	rand.Read(iv)
	ciphertext := make([]byte, 16+len(plaintext))
	stream := cipher.NewCTR(a.cipher, iv)
	stream.XORKeyStream(ciphertext[16:], plaintext)
	copy(ciphertext[:16], iv)
	return ciphertext
}

func (a *AES) decrypt(buf []byte) []byte {
	stream := cipher.NewCTR(a.cipher, buf[0:16])
	stream.XORKeyStream(buf[16:], buf[16:])
	return buf[16:]
}
