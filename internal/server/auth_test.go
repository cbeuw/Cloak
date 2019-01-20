package server

import (
	"bytes"
	"encoding/hex"
	"fmt"
	ecdh "github.com/cbeuw/go-ecdh"
	"testing"
)

var ec = ecdh.NewCurve25519ECDH()

func TestDecryptSessionTicket(t *testing.T) {
	UID, _ := hex.DecodeString("26a8e88bcd7c64a69ca051740851d22a6818de2fddafc00882331f1c5a8b866c")
	sessionID := uint32(42)
	pvb, _ := hex.DecodeString("083794692e77b28fa2152dfee53142185fd58ea8172d3545fdeeaea97b3c597c")
	staticPv, _ := ec.Unmarshal(pvb)
	sessionTicket, _ := hex.DecodeString("f586223b50cada583d61dc9bf3d01cc3a45aab4b062ed6a31ead0badb87f7761aab4f9f737a1d8ff2a2aa4d50ceb808844588ee3c8fdf36c33a35ef5003e287337659c8164a7949e9e63623090763fc24d0386c8904e47bdd740e09dd9b395c72de669629c2a865ed581452d23306adf26de0c8a46ee05e3dac876f2bcd9a2de946d319498f579383d06b3e66b3aca05f533fdc5f017eeba45b42080aabd4f71151fa0dfc1b0e23be4ed3abdb47adc0d5740ca7b7689ad34426309fb6984a086")

	decryUID, decrySessionID := decryptSessionTicket(staticPv, sessionTicket)
	if !bytes.Equal(decryUID, UID) {
		t.Error(
			"For", "UID",
			"expecting", fmt.Sprintf("%x", UID),
			"got", fmt.Sprintf("%x", decryUID),
		)
	}
	if decrySessionID != sessionID {
		t.Error(
			"For", "sessionID",
			"expecting", fmt.Sprintf("%x", sessionID),
			"got", fmt.Sprintf("%x", decrySessionID),
		)
	}

}

func TestValidateRandom(t *testing.T) {
	UID, _ := hex.DecodeString("26a8e88bcd7c64a69ca051740851d22a6818de2fddafc00882331f1c5a8b866c")
	random, _ := hex.DecodeString("6274de9992a6f96a86fc35cf6644a5e7844951889a802e9531add440eabb939b")
	right := validateRandom(random, UID, 1547912444)
	if !right {
		t.Error(
			"For", fmt.Sprintf("good random: %x at time %v", random, 1547912444),
			"expecting", true,
			"got", false,
		)
	}

	replay := validateRandom(random, UID, 1547955645)
	if replay {
		t.Error(
			"For", fmt.Sprintf("expired random: %x at time %v", random, 1547955645),
			"expecting", false,
			"got", true,
		)
	}

	random[13] = 0x42
	bogus := validateRandom(random, UID, 1547912444)
	if bogus {
		t.Error(
			"For", fmt.Sprintf("bogus random: %x at time %v", random, 1547912444),
			"expecting", false,
			"got", true,
		)
	}

}
