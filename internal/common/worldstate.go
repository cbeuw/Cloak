package common

import (
	"crypto/rand"
	"io"
	"time"
)

var RealWorldState = WorldState{
	Rand: rand.Reader,
	Now:  time.Now,
}

type WorldState struct {
	Rand io.Reader
	Now  func() time.Time
}
