package util

import (
	"io"
	"io/ioutil"
	"math/rand"
	"testing"
)

func BenchmarkPipe(b *testing.B) {
	reader := rand.New(rand.NewSource(42))
	buf := make([]byte, 16380)
	for i := 0; i < b.N; i++ {
		n, err := io.ReadAtLeast(reader, buf, 1)
		if err != nil {
			b.Error(err)
			return
		}
		n, err = ioutil.Discard.Write(buf[:n])
		if err != nil {
			b.Error(err)
			return
		}
		b.SetBytes(int64(n))
	}
}
