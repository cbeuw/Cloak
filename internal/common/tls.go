package common

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

const (
	VersionTLS11 = 0x0301
	VersionTLS13 = 0x0303

	recordLayerLength = 5

	Handshake       = 22
	ApplicationData = 23

	initialWriteBufSize = 14336
)

func AddRecordLayer(input []byte, typ byte, ver uint16) []byte {
	msgLen := len(input)
	retLen := msgLen + recordLayerLength
	var ret []byte
	ret = make([]byte, retLen)
	copy(ret[recordLayerLength:], input)
	ret[0] = typ
	ret[1] = byte(ver >> 8)
	ret[2] = byte(ver)
	ret[3] = byte(msgLen >> 8)
	ret[4] = byte(msgLen)
	return ret
}

type TLSConn struct {
	net.Conn
	writeM   sync.Mutex
	writeBuf []byte
}

func NewTLSConn(conn net.Conn) *TLSConn {
	writeBuf := make([]byte, initialWriteBufSize)
	writeBuf[0] = ApplicationData
	writeBuf[1] = byte(VersionTLS13 >> 8)
	writeBuf[2] = byte(VersionTLS13 & 0xFF)
	return &TLSConn{
		Conn:     conn,
		writeBuf: writeBuf,
	}
}

func (tls *TLSConn) LocalAddr() net.Addr {
	return tls.Conn.LocalAddr()
}

func (tls *TLSConn) RemoteAddr() net.Addr {
	return tls.Conn.RemoteAddr()
}

func (tls *TLSConn) SetDeadline(t time.Time) error {
	return tls.Conn.SetDeadline(t)
}

func (tls *TLSConn) SetReadDeadline(t time.Time) error {
	return tls.Conn.SetReadDeadline(t)
}

func (tls *TLSConn) SetWriteDeadline(t time.Time) error {
	return tls.Conn.SetWriteDeadline(t)
}

func (tls *TLSConn) Read(buffer []byte) (n int, err error) {
	// TCP is a stream. Multiple TLS messages can arrive at the same time,
	// a single message can also be segmented due to MTU of the IP layer.
	// This function guareentees a single TLS message to be read and everything
	// else is left in the buffer.
	if len(buffer) < recordLayerLength {
		return 0, io.ErrShortBuffer
	}
	_, err = io.ReadFull(tls.Conn, buffer[:recordLayerLength])
	if err != nil {
		return
	}

	dataLength := int(binary.BigEndian.Uint16(buffer[3:5]))
	if dataLength > len(buffer) {
		err = io.ErrShortBuffer
		return
	}
	// we overwrite the record layer here
	return io.ReadFull(tls.Conn, buffer[:dataLength])
}

func (tls *TLSConn) Write(in []byte) (n int, err error) {
	msgLen := len(in)
	tls.writeM.Lock()
	tls.writeBuf = append(tls.writeBuf[:5], in...)
	tls.writeBuf[3] = byte(msgLen >> 8)
	tls.writeBuf[4] = byte(msgLen & 0xFF)
	n, err = tls.Conn.Write(tls.writeBuf[:recordLayerLength+msgLen])
	tls.writeM.Unlock()
	return n - recordLayerLength, err
}

func (tls *TLSConn) Close() error {
	return tls.Conn.Close()
}
