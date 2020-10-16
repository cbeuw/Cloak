// +build gofuzz

package multiplex

func setupSesh_fuzz(unordered bool) *Session {
	obfuscator, _ := MakeObfuscator(E_METHOD_PLAIN, [32]byte{})

	seshConfig := SessionConfig{
		Obfuscator: obfuscator,
		Valve:      nil,
		Unordered:  unordered,
	}
	return MakeSession(0, seshConfig)
}

func Fuzz(data []byte) int {
	sesh := setupSesh_fuzz(false)
	err := sesh.recvDataFromRemote(data)
	if err == nil {
		return 1
	}
	return 0
}
