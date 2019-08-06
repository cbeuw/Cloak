package client

import (
	"encoding/binary"
	"github.com/cbeuw/Cloak/internal/util"
	"net"

	log "github.com/sirupsen/logrus"
)

type Browser interface {
	composeClientHello(*State) ([]byte, []byte)
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

// composeClientHello composes ClientHello with record layer
func composeClientHello(sta *State) ([]byte, []byte) {
	ch, sharedSecret := sta.Browser.composeClientHello(sta)
	return util.AddRecordLayer(ch, []byte{0x16}, []byte{0x03, 0x01}), sharedSecret
}

func PrepareConnection(sta *State, conn net.Conn) (sessionKey []byte, err error) {

	clientHello, sharedSecret := composeClientHello(sta)
	_, err = conn.Write(clientHello)
	if err != nil {
		return
	}
	log.Trace("client hello sent successfully")

	buf := make([]byte, 1024)
	log.Trace("waiting for ServerHello")
	_, err = util.ReadTLS(conn, buf)
	if err != nil {
		return
	}
	serverRandom := buf[11:43]
	sessionKey = decryptSessionKey(serverRandom, sharedSecret)
	_, err = util.ReadTLS(conn, buf)
	if err != nil {
		return
	}

	return sessionKey, nil

}
