package client

import (
	"github.com/cbeuw/Cloak/internal/common"
	mux "github.com/cbeuw/Cloak/internal/multiplex"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

var baseConfig = Config{
	ServerName:  "www.bing.com",
	ProxyMethod: "ssh",
	UID:         []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf},
	PublicKey:   make([]byte, 32),
	RemoteHost:  "12.34.56.78",
}

func TestDefault(t *testing.T) {
	remote, auth, err := baseConfig.Process(common.RealWorldState)
	assert.NoError(t, err)

	assert.EqualValues(t, 4, remote.NumConn)
	assert.EqualValues(t, mux.EncryptionMethodAES256GCM, auth.EncryptionMethod)
	assert.EqualValues(t, -1, remote.KeepAlive)
	assert.False(t, auth.Unordered)
}

func TestValidation(t *testing.T) {
	_, _, err := baseConfig.Process(common.RealWorldState)
	assert.NoError(t, err)

	type test struct {
		fieldToChange string
		newValue      any
		errPattern    string
	}

	tests := []test{
		{
			fieldToChange: "ServerName",
			newValue:      "",
			errPattern:    "empty",
		},
		{
			fieldToChange: "UID",
			newValue:      []byte{},
			errPattern:    "empty",
		},
		{
			fieldToChange: "PublicKey",
			newValue:      []byte{0x1},
			errPattern:    "unmarshal",
		},
		{
			fieldToChange: "RemoteHost",
			newValue:      "",
			errPattern:    "empty",
		},
		{
			fieldToChange: "BrowserSig",
			newValue:      "not-a-browser",
			errPattern:    "unknown",
		},
	}

	for _, test := range tests {
		config := baseConfig
		reflect.ValueOf(&config).Elem().FieldByName(test.fieldToChange).Set(reflect.ValueOf(test.newValue))
		_, _, err := config.Process(common.RealWorldState)
		assert.ErrorContains(t, err, test.errPattern)
	}
}
