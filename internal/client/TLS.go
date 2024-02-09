package client

import (
	utls "github.com/refraction-networking/utls"
	log "github.com/sirupsen/logrus"
	"net"

	"github.com/cbeuw/Cloak/internal/common"
)

const appDataMaxLength = 16401

type clientHelloFields struct {
	random         []byte
	sessionId      []byte
	x25519KeyShare []byte
	serverName     string
}

type browser int

const (
	chrome = iota
	firefox
	safari
)

type DirectTLS struct {
	*common.TLSConn
	browser browser
}

func buildClientHello(browser browser, fields clientHelloFields) ([]byte, error) {
	// We don't use utls to handle connections (as it'll attempt a real TLS negotiation)
	// We only want it to build the ClientHello locally
	fakeConn := net.TCPConn{}
	var helloID utls.ClientHelloID
	switch browser {
	case chrome:
		helloID = utls.HelloChrome_Auto
	case firefox:
		helloID = utls.HelloFirefox_Auto
	case safari:
		helloID = utls.HelloSafari_Auto
	}

	uclient := utls.UClient(&fakeConn, &utls.Config{ServerName: fields.serverName}, helloID)
	if err := uclient.BuildHandshakeState(); err != nil {
		return []byte{}, err
	}
	if err := uclient.SetClientRandom(fields.random); err != nil {
		return []byte{}, err
	}

	uclient.HandshakeState.Hello.SessionId = make([]byte, 32)
	copy(uclient.HandshakeState.Hello.SessionId, fields.sessionId)

	// Find the X25519 key share and overwrite it
	var extIndex int
	var keyShareIndex int
	for i, ext := range uclient.Extensions {
		ext, ok := ext.(*utls.KeyShareExtension)
		if ok {
			extIndex = i
			for j, keyShare := range ext.KeyShares {
				if keyShare.Group == utls.X25519 {
					keyShareIndex = j
				}
			}
		}
	}
	copy(uclient.Extensions[extIndex].(*utls.KeyShareExtension).KeyShares[keyShareIndex].Data, fields.x25519KeyShare)

	if err := uclient.BuildHandshakeState(); err != nil {
		return []byte{}, err
	}
	return uclient.HandshakeState.Hello.Raw, nil
}

// Handshake handles the TLS handshake for a given conn and returns the sessionKey
// if the server proceed with Cloak authentication
func (tls *DirectTLS) Handshake(rawConn net.Conn, authInfo AuthInfo) (sessionKey [32]byte, err error) {
	payload, sharedSecret := makeAuthenticationPayload(authInfo)

	fields := clientHelloFields{
		random:         payload.randPubKey[:],
		sessionId:      payload.ciphertextWithTag[0:32],
		x25519KeyShare: payload.ciphertextWithTag[32:64],
		serverName:     authInfo.MockDomain,
	}

	var ch []byte
	ch, err = buildClientHello(tls.browser, fields)
	if err != nil {
		return
	}
	chWithRecordLayer := common.AddRecordLayer(ch, common.Handshake, common.VersionTLS11)
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
