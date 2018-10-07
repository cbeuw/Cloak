// Chrome 64

package TLS

import (
	"encoding/hex"
	"math/rand"
	"time"

	"github.com/cbeuw/Cloak/internal/client"
	"github.com/cbeuw/Cloak/internal/util"
)

type chrome struct {
	browser
}

func (c *chrome) composeExtensions(sta *client.State) []byte {
	// see https://tools.ietf.org/html/draft-davidben-tls-grease-01
	// This is exclusive to chrome.
	makeGREASE := func() []byte {
		rand.Seed(time.Now().UnixNano())
		sixteenth := rand.Intn(16)
		monoGREASE := byte(sixteenth*16 + 0xA)
		doubleGREASE := []byte{monoGREASE, monoGREASE}
		return doubleGREASE
	}

	makeSupportedGroups := func() []byte {
		suppGroupListLen := []byte{0x00, 0x08}
		ret := make([]byte, 2+8)
		copy(ret[0:2], suppGroupListLen)
		copy(ret[2:4], makeGREASE())
		copy(ret[4:], []byte{0x00, 0x1d, 0x00, 0x17, 0x00, 0x18})
		return ret
	}

	var ext [14][]byte
	ext[0] = addExtRec(makeGREASE(), nil)                                 // First GREASE
	ext[1] = addExtRec([]byte{0xff, 0x01}, []byte{0x00})                  // renegotiation_info
	ext[2] = addExtRec([]byte{0x00, 0x00}, makeServerName(sta))           // server name indication
	ext[3] = addExtRec([]byte{0x00, 0x17}, nil)                           // extended_master_secret
	ext[4] = addExtRec([]byte{0x00, 0x23}, client.MakeSessionTicket(sta)) // Session tickets
	sigAlgo, _ := hex.DecodeString("0012040308040401050308050501080606010201")
	ext[5] = addExtRec([]byte{0x00, 0x0d}, sigAlgo)                              // Signature Algorithms
	ext[6] = addExtRec([]byte{0x00, 0x05}, []byte{0x01, 0x00, 0x00, 0x00, 0x00}) // status request
	ext[7] = addExtRec([]byte{0x00, 0x12}, nil)                                  // signed cert timestamp
	APLN, _ := hex.DecodeString("000c02683208687474702f312e31")
	ext[8] = addExtRec([]byte{0x00, 0x10}, APLN)                            // app layer proto negotiation
	ext[9] = addExtRec([]byte{0x75, 0x50}, nil)                             // channel id
	ext[10] = addExtRec([]byte{0x00, 0x0b}, []byte{0x01, 0x00})             // ec point formats
	ext[11] = addExtRec([]byte{0x00, 0x0a}, makeSupportedGroups())          // supported groups
	ext[12] = addExtRec(makeGREASE(), []byte{0x00})                         // Last GREASE
	ext[13] = addExtRec([]byte{0x00, 0x15}, makeNullBytes(110-len(ext[2]))) // padding
	var ret []byte
	for i := 0; i < 14; i++ {
		ret = append(ret, ext[i]...)
	}
	return ret
}

func (c *chrome) composeClientHello(sta *client.State) []byte {
	var clientHello [12][]byte
	clientHello[0] = []byte{0x01}                                  // handshake type
	clientHello[1] = []byte{0x00, 0x01, 0xfc}                      // length 508
	clientHello[2] = []byte{0x03, 0x03}                            // client version
	clientHello[3] = client.MakeRandomField(sta)                   // random
	clientHello[4] = []byte{0x20}                                  // session id length 32
	clientHello[5] = util.PsudoRandBytes(32, sta.Now().UnixNano()) // session id
	clientHello[6] = []byte{0x00, 0x1c}                            // cipher suites length 28
	cipherSuites, _ := hex.DecodeString("2a2ac02bc02fc02cc030cca9cca8c013c014009c009d002f0035000a")
	clientHello[7] = cipherSuites              // cipher suites
	clientHello[8] = []byte{0x01}              // compression methods length 1
	clientHello[9] = []byte{0x00}              // compression methods
	clientHello[10] = []byte{0x01, 0x97}       // extensions length 407
	clientHello[11] = c.composeExtensions(sta) // extensions
	var ret []byte
	for i := 0; i < 12; i++ {
		ret = append(ret, clientHello[i]...)
	}
	return ret
}
