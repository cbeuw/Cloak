package main

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/cbeuw/Cloak/internal/ecdh"
)

var b64 = base64.StdEncoding.EncodeToString

func generateUID() string {
	UID := make([]byte, 32)
	rand.Read(UID)
	return b64(UID)
}

func generateKeyPair() (string, string) {
	staticPv, staticPub, _ := ecdh.GenerateKey(rand.Reader)
	marshPub := ecdh.Marshal(staticPub)
	marshPv := staticPv.(*[32]byte)[:]
	return b64(marshPub), b64(marshPv)
}
