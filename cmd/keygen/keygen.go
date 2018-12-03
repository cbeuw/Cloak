package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	ecdh "github.com/cbeuw/go-ecdh"
)

var b64 = base64.StdEncoding.EncodeToString

func main() {

	UID := make([]byte, 32)
	rand.Read(UID)

	ec := ecdh.NewCurve25519ECDH()
	staticPv, staticPub, _ := ec.GenerateKey(rand.Reader)
	marshPub := ec.Marshal(staticPub)
	marshPv := staticPv.(*[32]byte)[:]

	fmt.Printf("USER: \n")
	fmt.Printf("\"UID\":\"%v\",\n", b64(UID))
	fmt.Printf("\"PublicKey\":\"%v\"\n", b64(marshPub))

	fmt.Println("=========================================")

	fmt.Printf("SERVER: \n")
	fmt.Printf("\"PrivateKey\":\"%v\"\n", b64(marshPv))
}
