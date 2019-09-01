package util

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
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

// ReadTLS reads TLS data according to its record layer
func ReadTLS(conn net.Conn, buffer []byte) (n int, err error) {
	// TCP is a stream. Multiple TLS messages can arrive at the same time,
	// a single message can also be segmented due to MTU of the IP layer.
	// This function guareentees a single TLS message to be read and everything
	// else is left in the buffer.
	i, err := io.ReadFull(conn, buffer[:5])
	if err != nil {
		return
	}

	dataLength := int(binary.BigEndian.Uint16(buffer[3:5]))
	if dataLength > len(buffer) {
		err = errors.New("Reading TLS message: message size greater than buffer. message size: " + strconv.Itoa(dataLength))
		return
	}
	left := dataLength
	readPtr := 5

	for left != 0 {
		// If left > buffer size (i.e. our message got segmented), the entire MTU is read
		// if left = buffer size, the entire buffer is all there left to read
		// if left < buffer size (i.e. multiple messages came together),
		// only the message we want is read

		i, err = conn.Read(buffer[readPtr : readPtr+left])
		if err != nil {
			return
		}
		left -= i
		readPtr += i
	}

	n = 5 + dataLength
	return
}

// AddRecordLayer adds record layer to data
func AddRecordLayer(input []byte, typ []byte, ver []byte) []byte {
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(input)))
	ret := make([]byte, 5+len(input))
	copy(ret[0:1], typ)
	copy(ret[1:3], ver)
	copy(ret[3:5], length)
	copy(ret[5:], input)
	return ret
}

func Pipe(dst net.Conn, src net.Conn, srcReadTimeout time.Duration) {
	// The maximum size of TLS message will be 16380+14+16. 14 because of the stream header and 16
	// because of the salt/mac
	// 16408 is the max TLS message size on Firefox
	buf := make([]byte, 16378)
	if srcReadTimeout != 0 {
		src.SetReadDeadline(time.Now().Add(srcReadTimeout))
	}
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
		i, err = dst.Write(buf[:i])
		if err != nil {
			dst.Close()
			src.Close()
			return
		}
	}
}
