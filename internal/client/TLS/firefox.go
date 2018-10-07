// Firefox 58
package TLS

import (
	"encoding/hex"

	"github.com/cbeuw/Cloak/internal/client"
	"github.com/cbeuw/Cloak/internal/util"
)

type firefox struct {
	browser
}

func (f *firefox) composeExtensions(sta *client.State) []byte {
	var ext [10][]byte
	ext[0] = addExtRec([]byte{0x00, 0x00}, makeServerName(sta)) // server name indication
	ext[1] = addExtRec([]byte{0x00, 0x17}, nil)                 // extended_master_secret
	ext[2] = addExtRec([]byte{0xff, 0x01}, []byte{0x00})        // renegotiation_info
	suppGroup, _ := hex.DecodeString("0008001d001700180019")
	ext[3] = addExtRec([]byte{0x00, 0x0a}, suppGroup)                     // supported groups
	ext[4] = addExtRec([]byte{0x00, 0x0b}, []byte{0x01, 0x00})            // ec point formats
	ext[5] = addExtRec([]byte{0x00, 0x23}, client.MakeSessionTicket(sta)) // Session tickets
	APLN, _ := hex.DecodeString("000c02683208687474702f312e31")
	ext[6] = addExtRec([]byte{0x00, 0x10}, APLN)                                 // app layer proto negotiation
	ext[7] = addExtRec([]byte{0x00, 0x05}, []byte{0x01, 0x00, 0x00, 0x00, 0x00}) // status request
	sigAlgo, _ := hex.DecodeString("001604030503060308040805080604010501060102030201")
	ext[8] = addExtRec([]byte{0x00, 0x0d}, sigAlgo)                        // Signature Algorithms
	ext[9] = addExtRec([]byte{0x00, 0x15}, makeNullBytes(121-len(ext[0]))) // padding
	var ret []byte
	for i := 0; i < 10; i++ {
		ret = append(ret, ext[i]...)
	}
	return ret
}

func (f *firefox) composeClientHello(sta *client.State) []byte {
	var clientHello [12][]byte
	clientHello[0] = []byte{0x01}                                  // handshake type
	clientHello[1] = []byte{0x00, 0x01, 0xfc}                      // length 508
	clientHello[2] = []byte{0x03, 0x03}                            // client version
	clientHello[3] = client.MakeRandomField(sta)                   // random
	clientHello[4] = []byte{0x20}                                  // session id length 32
	clientHello[5] = util.PsudoRandBytes(32, sta.Now().UnixNano()) // session id
	clientHello[6] = []byte{0x00, 0x1e}                            // cipher suites length 28
	cipherSuites, _ := hex.DecodeString("c02bc02fcca9cca8c02cc030c00ac009c013c01400330039002f0035000a")
	clientHello[7] = cipherSuites              // cipher suites
	clientHello[8] = []byte{0x01}              // compression methods length 1
	clientHello[9] = []byte{0x00}              // compression methods
	clientHello[10] = []byte{0x01, 0x95}       // extensions length 405
	clientHello[11] = f.composeExtensions(sta) // extensions
	var ret []byte
	for i := 0; i < 12; i++ {
		ret = append(ret, clientHello[i]...)
	}
	return ret
}
