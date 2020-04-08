package common

import (
	"encoding/binary"
	"io"
	"net"
	"time"
)

const (
	VersionTLS11 = 0x0301
	VersionTLS13 = 0x0303

	Handshake       = 22
	ApplicationData = 23
)

func AddRecordLayer(input []byte, typ byte, ver uint16) []byte {
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(input)))
	ret := make([]byte, 5+len(input))
	ret[0] = typ
	binary.BigEndian.PutUint16(ret[1:3], ver)
	copy(ret[3:5], length)
	copy(ret[5:], input)
	return ret
}

type TLSConn struct {
	net.Conn
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
	_, err = io.ReadFull(tls.Conn, buffer[:5])
	if err != nil {
		return
	}

	dataLength := int(binary.BigEndian.Uint16(buffer[3:5]))
	if dataLength > len(buffer) {
		err = io.ErrShortBuffer
		return
	}
	return io.ReadFull(tls.Conn, buffer[:dataLength])
}

func (tls *TLSConn) Write(in []byte) (n int, err error) {
	// TODO: write record layer directly first?
	toWrite := AddRecordLayer(in, ApplicationData, VersionTLS13)
	return tls.Conn.Write(toWrite)
}

func (tls *TLSConn) Close() error {
	return tls.Conn.Close()
}
