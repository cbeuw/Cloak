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
	serverName := "github.com"
	keyShare, _ := hex.DecodeString("690f074f5c01756982269b66d58c90c47dc0f281d654c7b2c16f63c9033f5604")

	sni := makeServerName(serverName)

	result := (&Chrome{}).composeExtensions(sni, keyShare)
	target, _ := hex.DecodeString("8a8a00000000000f000d00000a6769746875622e636f6d00170000ff01000100000a000a00088a8a001d00170018000b00020100002300000010000e000c02683208687474702f312e31000500050100000000000d0012001004030804040105030805050108060601001200000033002b00298a8a000100001d0020690f074f5c01756982269b66d58c90c47dc0f281d654c7b2c16f63c9033f5604002d00020101002b000b0a3a3a0304030303020301001b00030200024a4a000100001500d2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
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
