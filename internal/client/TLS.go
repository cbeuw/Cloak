package client

import (
	"encoding/binary"
	"github.com/cbeuw/Cloak/internal/common"
	log "github.com/sirupsen/logrus"
	"net"
)

const appDataMaxLength = 16401

type clientHelloFields struct {
	random         []byte
	sessionId      []byte
	x25519KeyShare []byte
	sni            []byte
}

type browser interface {
	composeClientHello(clientHelloFields) []byte
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

func genStegClientHello(ai authenticationPayload, serverName string) (ret clientHelloFields) {
	// random is marshalled ephemeral pub key 32 bytes
	// The authentication ciphertext and its tag are then distributed among SessionId and X25519KeyShare
	ret.random = ai.randPubKey[:]
	ret.sessionId = ai.ciphertextWithTag[0:32]
	ret.x25519KeyShare = ai.ciphertextWithTag[32:64]
	ret.sni = makeServerName(serverName)
	return
}

type DirectTLS struct {
	*common.TLSConn
	browser browser
}

// NewClientTransport handles the TLS handshake for a given conn and returns the sessionKey
// if the server proceed with Cloak authentication
func (tls *DirectTLS) Handshake(rawConn net.Conn, authInfo AuthInfo) (sessionKey [32]byte, err error) {
	payload, sharedSecret := makeAuthenticationPayload(authInfo)
	chOnly := tls.browser.composeClientHello(genStegClientHello(payload, authInfo.MockDomain))
	chWithRecordLayer := common.AddRecordLayer(chOnly, common.Handshake, common.VersionTLS11)
	_, err = rawConn.Write(chWithRecordLayer)
	if err != nil {
		return
	}
	log.Trace("client hello sent successfully")
	tls.TLSConn = common.NewTLSConn(rawConn)

	buf := make([]byte, 1024)
	log.Trace("waiting for ServerHello")
	_, err = tls.Read(buf)
	if err != nil {
		return
	}

	encrypted := append(buf[6:38], buf[84:116]...)
	nonce := encrypted[0:12]
	ciphertextWithTag := encrypted[12:60]
	sessionKeySlice, err := common.AESGCMDecrypt(nonce, sharedSecret[:], ciphertextWithTag)
	if err != nil {
		return
	}
	copy(sessionKey[:], sessionKeySlice)

	for i := 0; i < 2; i++ {
		// ChangeCipherSpec and EncryptedCert (in the format of application data)
		_, err = tls.Read(buf)
		if err != nil {
			return
		}
	}
	return sessionKey, nil

}
