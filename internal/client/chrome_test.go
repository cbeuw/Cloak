package client

import (
	"encoding/hex"
	"testing"
)

func TestMakeGREASE(t *testing.T) {
	a := hex.EncodeToString(makeGREASE())
	if a[1] != 'a' || a[3] != 'a' {
		t.Errorf("GREASE got %v", a)
	}

	var GREASEs []string
	for i := 0; i < 50; i++ {
		GREASEs = append(GREASEs, hex.EncodeToString(makeGREASE()))
	}
	var eqCount int
	for _, g := range GREASEs {
		if a == g {
			eqCount++
		}
	}
	if eqCount > 40 {
		t.Error("GREASE is not random", GREASEs)
	}
}

func TestComposeExtension(t *testing.T) {
	serverName := "www.cloudflare.com"
	keyShare, _ := hex.DecodeString("811b3c1f32edabbf31edeab4b8e0f8eae58fc6b3c3c9c1809a137dbc2ab2293c")

	sni := makeServerName(serverName)

	result := (&Chrome{}).composeExtensions(sni, keyShare)
	target, _ := hex.DecodeString("fafa00000000001700150000127777772e636c6f7564666c6172652e636f6d00170000ff01000100000a000a00089a9a001d00170018000b00020100002300000010000e000c02683208687474702f312e31000500050100000000000d0012001004030804040105030805050108060601001200000033002b00299a9a000100001d0020811b3c1f32edabbf31edeab4b8e0f8eae58fc6b3c3c9c1809a137dbc2ab2293c002d00020101002b000b0a1a1a0304030303020301001b00030200023a3a000100001500ca00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	for p := 0; p < len(result); {
		// skip GREASEs
		if result[p]&0x0F == 0xA && result[p+1]&0x0F == 0xA {
			p += 2
			continue
		}
		if result[p] != target[p] {
			t.Errorf("inequality at %v", p)
		}
		p += 1
	}
}
