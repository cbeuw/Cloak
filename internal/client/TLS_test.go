package client

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func htob(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func TestMakeServerName(t *testing.T) {
	type testingPair struct {
		serverName string
		target     []byte
	}

	pairs := []testingPair{
		{
			"www.google.com",
			htob("001100000e7777772e676f6f676c652e636f6d"),
		},
		{
			"www.gstatic.com",
			htob("001200000f7777772e677374617469632e636f6d"),
		},
		{
			"googleads.g.doubleclick.net",
			htob("001e00001b676f6f676c656164732e672e646f75626c65636c69636b2e6e6574"),
		},
	}

	for _, p := range pairs {
		if !bytes.Equal(makeServerName(p.serverName), p.target) {
			t.Error(
				"for", p.serverName,
				"expecting", p.target,
				"got", makeServerName(p.serverName))
		}
	}
}
