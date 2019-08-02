package client

import (
	"bytes"
	"testing"
)

func TestSSVtoJson(t *testing.T) {
	ssv := "UID=iGAO85zysIyR4c09CyZSLdNhtP/ckcYu7nIPI082AHA=;PublicKey=IYoUzkle/T/kriE+Ufdm7AHQtIeGnBWbhhlTbmDpUUI=;ServerName=www.bing.com;NumConn=4;MaskBrowser=chrome;"
	json := ssvToJson(ssv)
	expected := []byte(`{"UID":"iGAO85zysIyR4c09CyZSLdNhtP/ckcYu7nIPI082AHA=","PublicKey":"IYoUzkle/T/kriE+Ufdm7AHQtIeGnBWbhhlTbmDpUUI=","ServerName":"www.bing.com","NumConn":4,"MaskBrowser":"chrome"}`)
	if !bytes.Equal(expected, json) {
		t.Error(
			"For", "ssvToJson",
			"expecting", string(expected),
			"got", string(json),
		)
	}

}
