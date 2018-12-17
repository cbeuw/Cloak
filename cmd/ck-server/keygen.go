package main

import (
	"crypto/rand"
	"encoding/base64"
	ecdh "github.com/cbeuw/go-ecdh"
)

var b64 = base64.StdEncoding.EncodeToString

func generateUID() string {
	UID := make([]byte, 32)
	rand.Read(UID)
	return b64(UID)
}

func generateKeyPair() (string, string) {
	ec := ecdh.NewCurve25519ECDH()
	staticPv, staticPub, _ := ec.GenerateKey(rand.Reader)
	marshPub := ec.Marshal(staticPub)
	marshPv := staticPv.(*[32]byte)[:]
	return b64(marshPub), b64(marshPv)
}
