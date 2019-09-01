package client

import (
	"encoding/binary"
	"github.com/cbeuw/Cloak/internal/util"
	"net"

	log "github.com/sirupsen/logrus"
)

type browser interface {
	composeClientHello(chHiddenData) []byte
}

func makeServerName(serverName string) []byte {
	serverNameListLength := make([]byte, 2)
	binary.BigEndian.PutUint16(serverNameListLength, uint16(len(serverName)+3))
	serverNameType := []byte{0x00} // host_name
	serverNameLength := make([]byte, 2)
	binary.BigEndian.PutUint16(serverNameLength, uint16(len(serverName)))
	ret := make([]byte, 2+1+2+len(serverName))
	copy(ret[0:2], serverNameListLength)
	copy(ret[2:3], serverNameType)
	copy(ret[3:5], serverNameLength)
	copy(ret[5:], serverName)
	return ret
}

// addExtensionRecord, add type, length to extension data
func addExtRec(typ []byte, data []byte) []byte {
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(data)))
	ret := make([]byte, 2+2+len(data))
	copy(ret[0:2], typ)
	copy(ret[2:4], length)
	copy(ret[4:], data)
	return ret
}

type TLS struct {
	Transport
}

func (*TLS) HasRecordLayer() bool                              { return true }
func (*TLS) UnitReadFunc() func(net.Conn, []byte) (int, error) { return util.ReadTLS }

// PrepareConnection handles the TLS handshake for a given conn and returns the sessionKey
// if the server proceed with Cloak authentication
func (*TLS) PrepareConnection(sta *State, conn net.Conn) (preparedConn net.Conn, sessionKey []byte, err error) {
	preparedConn = conn
	hd, sharedSecret := makeHiddenData(sta)
	chOnly := sta.browser.composeClientHello(hd)
	chWithRecordLayer := util.AddRecordLayer(chOnly, []byte{0x16}, []byte{0x03, 0x01})
	_, err = preparedConn.Write(chWithRecordLayer)
	if err != nil {
		return
	}
	log.Trace("client hello sent successfully")

	buf := make([]byte, 1024)
	log.Trace("waiting for ServerHello")
	_, err = util.ReadTLS(preparedConn, buf)
	if err != nil {
		return
	}

	encrypted := append(buf[11:43], buf[89:121]...)
	nonce := encrypted[0:12]
	ciphertextWithTag := encrypted[12:60]
	sessionKey, err = util.AESGCMDecrypt(nonce, sharedSecret, ciphertextWithTag)
	if err != nil {
		return
	}

	for i := 0; i < 2; i++ {
		// ChangeCipherSpec and EncryptedCert (in the format of application data)
		_, err = util.ReadTLS(preparedConn, buf)
		if err != nil {
			return
		}
	}

	return preparedConn, sessionKey, nil

}
