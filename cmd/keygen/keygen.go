package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	ecdh "github.com/cbeuw/go-ecdh"
)

var b64 = base64.StdEncoding.EncodeToString

func main() {
	var isUID *bool
	var isKeypair *bool
	isUID = flag.Bool("u", false, "Generate UID")
	isKeypair = flag.Bool("k", false, "Generate a key pair")
	flag.Parse()

	if *isUID {
		UID := make([]byte, 32)
		rand.Read(UID)
		fmt.Printf(b64(UID))
	} else if *isKeypair {
		ec := ecdh.NewCurve25519ECDH()
		staticPv, staticPub, _ := ec.GenerateKey(rand.Reader)
		marshPub := ec.Marshal(staticPub)
		marshPv := staticPv.(*[32]byte)[:]

		fmt.Printf("%v,%v", b64(marshPub), b64(marshPv))

	}
}
