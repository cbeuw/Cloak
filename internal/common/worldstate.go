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

func WorldOfTime(t time.Time) WorldState {
	return WorldState{
		Rand: rand.Reader,
		Now:  func() time.Time { return t },
	}
}
