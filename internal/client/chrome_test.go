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
	serverName := "cdn.bizible.com"
	keyShare, _ := hex.DecodeString("010a8896b68fb16e2a245ed87be2699348ab72068bb326eac5beaa00fa56ff17")

	sni := makeServerName(serverName)

	result := (&Chrome{}).composeExtensions(sni, keyShare)
	target, _ := hex.DecodeString("5a5a000000000014001200000f63646e2e62697a69626c652e636f6d00170000ff01000100000a000a0008fafa001d00170018000b00020100002300000010000e000c02683208687474702f312e31000500050100000000000d00140012040308040401050308050501080606010201001200000033002b0029fafa000100001d0020010a8896b68fb16e2a245ed87be2699348ab72068bb326eac5beaa00fa56ff17002d00020101002b000b0aaaaa0304030303020301001b0003020002eaea000100001500c9000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	for p := 0; p < len(result); {
		// skip GREASEs
		if p == 0 || p == 43 || p == 122 || p == 174 || p == 191 {
			p += 2
			continue
		}
		if result[p] != target[p] {
			t.Errorf("inequality at %v", p)
		}
		p += 1
	}
}
