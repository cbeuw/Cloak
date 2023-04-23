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

//func TestChromeJA3(t *testing.T) {
//	result := common.AddRecordLayer((&Chrome{}).composeClientHello(hd), common.Handshake, common.VersionTLS11)
//	assert.Equal(t, 517, len(result))
//
//	hello := tlsx.ClientHelloBasic{}
//	err := hello.Unmarshal(result)
//	assert.Nil(t, err)
//
//	// Chrome shuffles the order of extensions, so it needs special handling
//	full := string(ja3.Bare(&hello))
//	// TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
//	parts := strings.Split(full, ",")
//
//	// TLSVersion,Ciphers
//	assert.Equal(t,
//		[]string{
//			"771",
//			"4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53",
//		}, parts[0:2])
//	// EllipticCurves,EllipticCurvePointFormats
//	assert.Equal(t,
//		[]string{
//			"29-23-24", "0",
//		}, parts[3:5])
//
//	normaliseExtensions := func(extensions string) []string {
//		extensionParts := strings.Split(parts[2], "-")
//		sort.Strings(extensionParts)
//		return extensionParts
//	}
//	assert.Equal(t, normaliseExtensions("10-5-45-0-17513-13-18-11-23-16-35-27-65281-43-51-21"), normaliseExtensions(parts[2]))
//}
