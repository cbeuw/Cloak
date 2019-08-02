package multiplex

import (
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

func TestOobfs(t *testing.T) {
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	obfuscator, err := GenerateObfs(0x01, sessionKey)
	if err != nil {
		t.Errorf("failed to generate obfuscator %v", err)
	}

	f := &Frame{}
	_testFrame, _ := quick.Value(reflect.TypeOf(f), rand.New(rand.NewSource(42)))
	testFrame := _testFrame.Interface().(*Frame)
	obfsed, err := obfuscator.Obfs(testFrame)
	if err != nil {
		t.Error("failed to obfs ", err)
	}

	resultFrame, err := obfuscator.Deobfs(obfsed)
	if err != nil {
		t.Error("failed to deobfs ", err)
	}
	if !reflect.DeepEqual(testFrame, resultFrame) {
		t.Error("expecting", testFrame,
			"got", resultFrame)
	}

}
