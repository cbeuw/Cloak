package server

import (
	"bytes"
	//"bytes"
	"encoding/hex"
	"fmt"
	"github.com/cbeuw/Cloak/internal/ecdh"
	"testing"
	//"github.com/cbeuw/Cloak/internal/ecdh"
)

func TestDecryptSessionTicket(t *testing.T) {
	UID, _ := hex.DecodeString("4cd8cc15600d7eb68131fd8097673746")
	pvb, _ := hex.DecodeString("10de5a3c4a4d04efafc3e06d1506363a72bd6d053baef123e6a9a79a0c04b547")
	staticPv, _ := ecdh.Unmarshal(pvb)
	proxyMethod := "shadowsocks"
	encryptionMethod := byte(0)
	tthKey, _ := hex.DecodeString("92389a9b2769e2b76514c4cb163217bed0c5500bceb4a5ade1ceae597616db23")

	sessionTicket, _ := hex.DecodeString("9ee339202508b6fbe9c19988575330c547efbc27b0d072ed93c0cc265b67d826825a49211b8f86b4364b436ed5db15925774c3bec4a1776f70a17db68ba541dc4c23871d2cc1a5074b081bbe0f8b86f1c7f7749964517dcfd8830532eddc8ac707544ec04b754a133b9595ebc2af988156dbe1e4f3b89c9dc289d441cb5a15d72cc59423981d43a498292d509e5fa5c8e8bf8ee85a2e4991ae126fcd6e4d2aa1119e918c80afa2dc38bec1ef621c9c3994af43b1983c241c68e04e8043c95d74")

	decryUID, decryProxyMethod, decryEncryptionMethod, decryTthKey := decryptSessionTicket(staticPv, sessionTicket)

	if !bytes.Equal(decryUID, UID) {
		t.Error(
			"For", "UID",
			"expecting", fmt.Sprintf("%x", UID),
			"got", fmt.Sprintf("%x", decryUID),
		)
	}
	if proxyMethod != decryProxyMethod {
		t.Error(
			"For", "proxyMethod",
			"expecting", fmt.Sprintf("%x", proxyMethod),
			"got", fmt.Sprintf("%x", decryProxyMethod),
		)
	}
	if encryptionMethod != decryEncryptionMethod {
		t.Error(
			"For", "encryptionMethod",
			"expecting", fmt.Sprintf("%x", encryptionMethod),
			"got", fmt.Sprintf("%x", decryEncryptionMethod),
		)
	}
	if !bytes.Equal(tthKey, decryTthKey) {
		t.Error(
			"For", "tthKey",
			"expecting", fmt.Sprintf("%x", tthKey),
			"got", fmt.Sprintf("%x", decryTthKey),
		)
	}

}

func TestValidateRandom(t *testing.T) {
	sessionID := uint32(2422026642)
	random, _ := hex.DecodeString("905d319272711946f6400db4f5028d6893f7b22659c78371c1f72386191a8ab4")
	UID, _ := hex.DecodeString("4cd8cc15600d7eb68131fd8097673746")

	right, decrySessionID := validateRandom(random, UID, 1564150721)
	if !right {
		t.Error(
			"For", fmt.Sprintf("good random: %x at time %v", random, 1564150721),
			"expecting", true,
			"got", false,
		)
	}
	if sessionID != decrySessionID {
		t.Error(
			"For", fmt.Sprintf("good random: %x at time %v", random, 1564150721),
			"expecting", sessionID,
			"got", decrySessionID,
		)
	}

	replay, _ := validateRandom(random, UID, 1764150721)
	if replay {
		t.Error(
			"For", fmt.Sprintf("expired random: %x at time %v", random, 1764150721),
			"expecting", false,
			"got", true,
		)
	}

	random[13] = 0x42
	bogus, _ := validateRandom(random, UID, 1564150721)
	if bogus {
		t.Error(
			"For", fmt.Sprintf("bogus random: %x at time %v", random, 1564150721),
			"expecting", false,
			"got", true,
		)
	}

}
