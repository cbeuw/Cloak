package client

import (
	"bytes"
	"encoding/gob"
	//"crypto/aes"
	//"crypto/cipher"
	//"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	//prand "math/rand"
	"testing"
	"time"
	//"github.com/cbeuw/Cloak/internal/ecdh"
)

func TestMakeSessionTicket(t *testing.T) {

	stateGob, _ := hex.DecodeString("ffc5ff8103010105537461746501ff8200010c01094c6f63616c486f7374010c0001094c6f63616c506f7274010c00010a52656d6f7465486f7374010c00010a52656d6f7465506f7274010c00010953657373696f6e49440106000103554944010a00010b50726f78794d6574686f64010c000110456e6372797074696f6e4d6574686f64010600010e5469636b657454696d6548696e74010400010a5365727665724e616d65010c00010a42726f77736572536967010c0001074e756d436f6e6e010400000065ff8201093132372e302e302e3101043139383401093132372e302e302e31010334343301fc52fdfc0701104cd8cc15600d7eb68131fd8097673746010b736861646f77736f636b7302fe1c20010c7777772e62696e672e636f6d01066368726f6d65010800")
	buf := bytes.NewBuffer(stateGob)
	mockSta := &State{}
	gob.NewDecoder(buf).Decode(mockSta)
	mockSta.intervalData = &tthIntervalKeys{}
	mockSta.intervalData.interval = 434487
	ephPub, _ := hex.DecodeString("7b7e0db16bb8c83355771a424234e36c02fd752b6a9310968d27787d7c117b10")
	ephPv, _ := hex.DecodeString("68584fed8ede64e2b17619b9cc0effb2678feb2face92456a8414dafa629334b")
	mockSta.intervalData.intervalKey, _ = hex.DecodeString("47e1c2413f1a6b397fbd61d6cf21397b20a2338cef48fae68643602881d93d4b")
	mockSta.intervalData.seed = 7518847459617826018
	staticPub, _ := hex.DecodeString("218a14ce495efd3fe4ae213e51f766ec01d0b487869c159b8619536e60e95142")

	var a, b, c [32]byte
	copy(a[:], ephPub)
	copy(b[:], ephPv)
	copy(c[:], staticPub)
	mockSta.intervalData.ephPub = &a
	mockSta.intervalData.ephPv = &b
	mockSta.staticPub = &c

	target, _ := hex.DecodeString("7b7e0db16bb8c83355771a424234e36c02fd752b6a9310968d27787d7c117b103a2d246fd8b7d9e4243d6b83a7365858bd9cb583ba950287c4f4edc249cea935e235eda92c48569f455fca34ff6e4d37cf8f519b1d66e7cd51b31c1766ffb03134576e8d61ad5eae58a9ce4153ec33af73c7a8d04ab56d51155ac19fe731c792c17ee98a97fbfef8efc952964b7fd61dd2a35d7de4128abc730e20ba44e069e44ba8e29b66a8e4f114b9ab4cc2fba944a925086d7f09892a59147d990b58d393")
	ticket := MakeSessionTicket(mockSta)

	if !bytes.Equal(target, ticket) {
		t.Error(
			"For", "sessionTicket generation",
			"expecting", fmt.Sprintf("%x", target),
			"got", fmt.Sprintf("%x", ticket),
		)
	}

}

func TestMakeRandomField(t *testing.T) {
	UID, _ := hex.DecodeString("4cd8cc15600d7eb68131fd8097673746")
	mockSta := &State{
		Now:       time.Now,
		UID:       UID,
		SessionID: 1,
	}
	random := MakeRandomField(mockSta)

	// verification
	tb := make([]byte, 8)
	binary.BigEndian.PutUint64(tb, uint64(time.Now().Unix()/(12*60*60)))
	front := random[0:16]
	preHash := make([]byte, 56)
	copy(preHash[0:32], UID)
	copy(preHash[32:40], tb)
	copy(preHash[40:56], front)
	h := sha256.New()
	h.Write(preHash)
	exp := h.Sum(nil)[0:16]
	if !bytes.Equal(exp, random[16:32]) {
		t.Error(
			"For", "Random generation",
			"expecting", fmt.Sprintf("%x", exp),
			"got", fmt.Sprintf("%x", random[16:32]),
		)
	}

	random2 := MakeRandomField(mockSta)
	if bytes.Equal(random, random2) {
		t.Error(
			"For", "Duplicate random generation",
			"expecting", "two different randoms",
			"got", fmt.Sprintf("the same: %x", random),
		)
	}
}
