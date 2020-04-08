package main

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/cbeuw/Cloak/internal/ecdh"
	"github.com/cbeuw/Cloak/internal/util"
)

func generateUID() string {
	UID := make([]byte, 16)
	util.CryptoRandRead(UID)
	return base64.StdEncoding.EncodeToString(UID)
}

func generateKeyPair() (string, string) {
	staticPv, staticPub, _ := ecdh.GenerateKey(rand.Reader)
	marshPub := ecdh.Marshal(staticPub)
	marshPv := staticPv.(*[32]byte)[:]
	return base64.StdEncoding.EncodeToString(marshPub), base64.StdEncoding.EncodeToString(marshPv)
}
