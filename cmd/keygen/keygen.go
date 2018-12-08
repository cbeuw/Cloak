package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	ecdh "github.com/cbeuw/go-ecdh"
)

var b64 = base64.StdEncoding.EncodeToString

func main() {
	for {
		fmt.Println("1 to generate UID, 2 to generate a key pair")

		var sel int
		_, err := fmt.Scanln(&sel)
		if err != nil {
			fmt.Println("Please enter a number")
			continue
		}
		if sel != 1 && sel != 2 {
			fmt.Println("Please enter 1 or 2")
			continue
		}

		if sel == 1 {
			UID := make([]byte, 32)
			rand.Read(UID)
			fmt.Printf("\"UID\":\"%v\"\n", b64(UID))
		} else if sel == 2 {

			ec := ecdh.NewCurve25519ECDH()
			staticPv, staticPub, _ := ec.GenerateKey(rand.Reader)
			marshPub := ec.Marshal(staticPub)
			marshPv := staticPv.(*[32]byte)[:]

			fmt.Printf("USER: \n")
			fmt.Printf("\"PublicKey\":\"%v\"\n", b64(marshPub))

			fmt.Println("=========================================")

			fmt.Printf("SERVER: \n")
			fmt.Printf("\"PrivateKey\":\"%v\"\n", b64(marshPv))
		}
	}
}
