package client

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseConfig(t *testing.T) {
	ssv := "UID=iGAO85zysIyR4c09CyZSLdNhtP/ckcYu7nIPI082AHA=;PublicKey=IYoUzkle/T/kriE+Ufdm7AHQtIeGnBWbhhlTbmDpUUI=;" +
		"ServerName=www.bing.com;NumConn=4;MaskBrowser=chrome;ProxyMethod=shadowsocks;EncryptionMethod=plain"
	json := ssvToJson(ssv)
	expected := []byte(`{"UID":"iGAO85zysIyR4c09CyZSLdNhtP/ckcYu7nIPI082AHA=","PublicKey":"IYoUzkle/T/kriE+Ufdm7AHQtIeGnBWbhhlTbmDpUUI=","ServerName":"www.bing.com","NumConn":4,"MaskBrowser":"chrome","ProxyMethod":"shadowsocks","EncryptionMethod":"plain"}`)

	t.Run("byte equality", func(t *testing.T) {
		assert.Equal(t, expected, json)
	})

	t.Run("struct equality", func(t *testing.T) {
		tmpConfig, _ := ioutil.TempFile("", "ck_client_config")
		_, _ = tmpConfig.Write(expected)
		parsedFromSSV, err := ParseConfig(ssv)
		assert.NoError(t, err)
		parsedFromJson, err := ParseConfig(tmpConfig.Name())
		assert.NoError(t, err)

		assert.Equal(t, parsedFromJson, parsedFromSSV)
	})

	t.Run("empty file", func(t *testing.T) {
		tmpConfig, _ := ioutil.TempFile("", "ck_client_config")
		_, err := ParseConfig(tmpConfig.Name())
		assert.Error(t, err)
	})

}
