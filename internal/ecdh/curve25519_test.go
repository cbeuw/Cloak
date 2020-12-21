// This code is forked from https://github.com/wsddn/go-ecdh/blob/master/curve25519.go
/*
Copyright (c) 2014, tang0th
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of tang0th nor the names of its contributors may be
      used to endorse or promote products derived from this software without
      specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package ecdh

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"io"
	"testing"
)

func TestCurve25519(t *testing.T) {
	testECDH(t)
}

func TestErrors(t *testing.T) {
	reader, writer := io.Pipe()
	_ = writer.Close()
	_, _, err := GenerateKey(reader)
	if err == nil {
		t.Error("GenerateKey should return error")
	}

	_, ok := Unmarshal([]byte{1})
	if ok {
		t.Error("Unmarshal should return false")
	}
}

func BenchmarkCurve25519(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testECDH(b)
	}
}

func testECDH(t testing.TB) {
	var privKey1, privKey2 crypto.PrivateKey
	var pubKey1, pubKey2 crypto.PublicKey
	var pubKey1Buf, pubKey2Buf []byte
	var err error
	var ok bool
	var secret1, secret2 []byte

	privKey1, pubKey1, err = GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
	privKey2, pubKey2, err = GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}

	pubKey1Buf = Marshal(pubKey1)
	pubKey2Buf = Marshal(pubKey2)

	pubKey1, ok = Unmarshal(pubKey1Buf)
	if !ok {
		t.Fatalf("Unmarshal does not work")
	}

	pubKey2, ok = Unmarshal(pubKey2Buf)
	if !ok {
		t.Fatalf("Unmarshal does not work")
	}

	secret1, err = GenerateSharedSecret(privKey1, pubKey2)
	if err != nil {
		t.Error(err)
	}
	secret2, err = GenerateSharedSecret(privKey2, pubKey1)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(secret1, secret2) {
		t.Fatalf("The two shared keys: %d, %d do not match", secret1, secret2)
	}
}
