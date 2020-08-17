package multiplex

import (
	"sync/atomic"

	"github.com/juju/ratelimit"
)

// Valve needs to be universal, across all sessions that belong to a user
type LimitedValve struct {
	// traffic directions from the server's perspective are referred
	// exclusively as rx and tx.
	// rx is from client to server, tx is from server to client
	// DO NOT use terms up or down as this is used in usermanager
	// for bandwidth limiting
	rxtb *ratelimit.Bucket
	txtb *ratelimit.Bucket

	rx *int64
	tx *int64
}

type UnlimitedValve struct{}

func MakeValve(rxRate, txRate int64) *LimitedValve {
	var rx, tx int64
	v := &LimitedValve{
		rxtb: ratelimit.NewBucketWithRate(float64(rxRate), rxRate),
		txtb: ratelimit.NewBucketWithRate(float64(txRate), txRate),
		rx:   &rx,
		tx:   &tx,
	}
	return v
}

var UNLIMITED_VALVE = &UnlimitedValve{}

func (v *LimitedValve) rxWait(n int)  { v.rxtb.Wait(int64(n)) }
func (v *LimitedValve) txWait(n int)  { v.txtb.Wait(int64(n)) }
func (v *LimitedValve) AddRx(n int64) { atomic.AddInt64(v.rx, n) }
func (v *LimitedValve) AddTx(n int64) { atomic.AddInt64(v.tx, n) }
func (v *LimitedValve) GetRx() int64  { return atomic.LoadInt64(v.rx) }
func (v *LimitedValve) GetTx() int64  { return atomic.LoadInt64(v.tx) }
func (v *LimitedValve) Nullify() (int64, int64) {
	rx := atomic.SwapInt64(v.rx, 0)
	tx := atomic.SwapInt64(v.tx, 0)
	return rx, tx
}

func (v *UnlimitedValve) rxWait(n int)            {}
func (v *UnlimitedValve) txWait(n int)            {}
func (v *UnlimitedValve) AddRx(n int64)           {}
func (v *UnlimitedValve) AddTx(n int64)           {}
func (v *UnlimitedValve) GetRx() int64            { return 0 }
func (v *UnlimitedValve) GetTx() int64            { return 0 }
func (v *UnlimitedValve) Nullify() (int64, int64) { return 0, 0 }

type Valve interface {
	rxWait(n int)
	txWait(n int)
	AddRx(n int64)
	AddTx(n int64)
	GetRx() int64
	GetTx() int64
	Nullify() (int64, int64)
}
