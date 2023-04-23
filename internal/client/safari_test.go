package client

import (
	"github.com/cbeuw/Cloak/internal/common"
	"github.com/dreadl0ck/ja3"
	"github.com/dreadl0ck/tlsx"
	"github.com/stretchr/testify/assert"
	"testing"
)

var safariHd = clientHelloFields{
	random:         decodeHex("977ecef48c0fc5640fea4dbd638da89704d6d85ed2e81b8913ae5b27f9a5cc17"),
	sessionId:      decodeHex("c2d5b91e77371bf154363b39194ac77c05617cc6164724d0ba7ded4aa349c6a3"),
	x25519KeyShare: decodeHex("c99fbe80dda71f6e24d9b798dc3f3f33cef946f0b917fa90154a4b95114fae2a"),
	serverName:     "github.com",
}

func TestSafariJA3(t *testing.T) {
	result := common.AddRecordLayer((&Safari{}).composeClientHello(safariHd), common.Handshake, common.VersionTLS11)

	hello := tlsx.ClientHelloBasic{}
	err := hello.Unmarshal(result)
	assert.Nil(t, err)

	digest := ja3.DigestHex(&hello)
	assert.Equal(t, "773906b0efdefa24a7f2b8eb6985bf37", digest)
}

func TestSafariComposeClientHello(t *testing.T) {
	result := (&Safari{}).composeClientHello(safariHd)
	target := decodeHex("010001fc0303977ecef48c0fc5640fea4dbd638da89704d6d85ed2e81b8913ae5b27f9a5cc1720c2d5b91e77371bf154363b39194ac77c05617cc6164724d0ba7ded4aa349c6a3002acaca130113021303c02cc02bcca9c030c02fcca8c00ac009c014c013009d009c0035002fc008c012000a01000189fafa00000000000f000d00000a6769746875622e636f6d00170000ff01000100000a000c000a7a7a001d001700180019000b000201000010000e000c02683208687474702f312e31000500050100000000000d0018001604030804040105030203080508050501080606010201001200000033002b00297a7a000100001d0020c99fbe80dda71f6e24d9b798dc3f3f33cef946f0b917fa90154a4b95114fae2a002d00020101002b000b0a2a2a0304030303020301001b00030200017a7a000100001500c400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	for p := 0; p < len(result); p++ {
		if result[p] != target[p] {
			if result[p]&0x0F == 0xA && target[p]&0x0F == 0xA &&
				((p > 0 && result[p-1] == result[p] && target[p-1] == target[p]) ||
					(p < len(result)-1 && result[p+1] == result[p] && target[p+1] == target[p])) {
				continue
			}
			t.Errorf("inequality at %v", p)
		}
	}
}