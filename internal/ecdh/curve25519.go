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
	"crypto"
	"io"

	"golang.org/x/crypto/curve25519"
)

func GenerateKey(rand io.Reader) (crypto.PrivateKey, crypto.PublicKey, error) {
	var pub, priv [32]byte
	var err error

	_, err = io.ReadFull(rand, priv[:])
	if err != nil {
		return nil, nil, err
	}

	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	curve25519.ScalarBaseMult(&pub, &priv)

	return &priv, &pub, nil
}

func Marshal(p crypto.PublicKey) []byte {
	pub := p.(*[32]byte)
	return pub[:]
}

func Unmarshal(data []byte) (crypto.PublicKey, bool) {
	var pub [32]byte
	if len(data) != 32 {
		return nil, false
	}

	copy(pub[:], data)
	return &pub, true
}

func GenerateSharedSecret(privKey crypto.PrivateKey, pubKey crypto.PublicKey) ([]byte, error) {
	var priv, pub *[32]byte

	priv = privKey.(*[32]byte)
	pub = pubKey.(*[32]byte)

	return curve25519.X25519(priv[:], pub[:])
}
