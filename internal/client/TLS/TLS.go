package TLS

import (
	"encoding/binary"
	"github.com/cbeuw/Cloak/internal/client"
	"github.com/cbeuw/Cloak/internal/util"
	"time"
)

type browser interface {
	composeExtensions()
	composeClientHello()
}

func makeServerName(sta *client.State) []byte {
	serverName := sta.ServerName
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

func makeNullBytes(length int) []byte {
	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		ret[i] = 0x00
	}
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

// ComposeInitHandshake composes ClientHello with record layer
func ComposeInitHandshake(sta *client.State) []byte {
	var ch []byte
	switch sta.BrowserSig {
	case "chrome":
		ch = (&chrome{}).composeClientHello(sta)
	case "firefox":
		ch = (&firefox{}).composeClientHello(sta)
	default:
		panic("Unsupported browser:" + sta.BrowserSig)
	}
	return util.AddRecordLayer(ch, []byte{0x16}, []byte{0x03, 0x01})
}

// ComposeReply composes RL+ChangeCipherSpec+RL+Finished
func ComposeReply() []byte {
	TLS12 := []byte{0x03, 0x03}
	ccsBytes := util.AddRecordLayer([]byte{0x01}, []byte{0x14}, TLS12)
	finished := util.PsudoRandBytes(40, time.Now().UnixNano())
	fBytes := util.AddRecordLayer(finished, []byte{0x16}, TLS12)
	return append(ccsBytes, fBytes...)
}
