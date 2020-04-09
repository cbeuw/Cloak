package integration_test

import (
	"encoding/base64"
	"github.com/cbeuw/Cloak/internal/client"
	"github.com/cbeuw/Cloak/internal/server"
)

var bypassUID = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
var publicKey, _ = base64.StdEncoding.DecodeString("7f7TuKrs264VNSgMno8PkDlyhGhVuOSR8JHLE6H4Ljc=")
var privateKey, _ = base64.StdEncoding.DecodeString("SMWeC6VuZF8S/id65VuFQFlfa7hTEJBpL6wWhqPP100=")

var clientConfig = client.RawConfig{
	ServerName:       "www.example.com",
	ProxyMethod:      "test",
	EncryptionMethod: "plain",
	UID:              bypassUID,
	PublicKey:        publicKey,
	NumConn:          3,
	UDP:              false,
	BrowserSig:       "chrome",
	Transport:        "direct",
}

var serverState = server.State{
	ProxyBook:      nil,
	ProxyDialer:    nil,
	AdminUID:       nil,
	Timeout:        0,
	BypassUID:      nil,
	RedirHost:      nil,
	RedirPort:      "",
	RedirDialer:    nil,
	Panel:          nil,
	LocalAPIRouter: nil,
}
