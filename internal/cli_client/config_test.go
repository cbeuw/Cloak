package cli_client

import (
	"github.com/cbeuw/Cloak/internal/common"
	"github.com/cbeuw/Cloak/libcloak/client"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
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

func TestProcessCLIConfig(t *testing.T) {
	config := CLIConfig{
		Config: client.Config{
			ServerName: "bbc.co.uk",
			// ProxyMethod is the name of the underlying proxy you wish
			// to connect to, as determined by your server. The value can
			// be any string whose UTF-8 ENCODED byte length is no greater than
			// 12 bytes
			ProxyMethod: "ssh",
			// UID is a 16-byte secret string unique to an authorised user
			// The same UID can be used by the same user for multiple Cloak connections
			UID: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			// PublicKey is the 32-byte public Curve25519 ECDH key of your server
			PublicKey: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			// RemoteHost is the Cloak server's hostname or IP address
			RemoteHost: "1.2.3.4",
		},
		LocalHost: "0.0.0.0",
		LocalPort: "1234",
	}

	t.Run("Zero means singleplex", func(t *testing.T) {
		zero := 0
		config := config
		config.NumConn = &zero
		local, _, _, err := config.ProcessCLIConfig(common.RealWorldState)
		assert.NoError(t, err)
		assert.True(t, local.Singleplex)
	})

	t.Run("Empty means no singleplex", func(t *testing.T) {
		config := config
		local, _, _, err := config.ProcessCLIConfig(common.RealWorldState)
		assert.NoError(t, err)
		assert.False(t, local.Singleplex)
	})
}
