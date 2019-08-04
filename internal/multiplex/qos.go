package multiplex

import (
	"sync/atomic"

	"github.com/cbeuw/ratelimit"
)

// Valve needs to be universal, across all sessions that belong to a user
// gabe please don't sue
type Valve struct {
	// traffic directions from the server's perspective are refered
	// exclusively as rx and tx.
	// rx is from client to server, tx is from server to client
	// DO NOT use terms up or down as this is used in usermanager
	// for bandwidth limiting
	rxtb ratelimit.Bucket
	txtb ratelimit.Bucket

	rx *int64
	tx *int64
}

func MakeValve(rxRate, txRate int64) *Valve {
	var rx, tx int64
	v := &Valve{
		rxtb: ratelimit.NewLimitedBucketWithRate(float64(rxRate), rxRate),
		txtb: ratelimit.NewLimitedBucketWithRate(float64(txRate), txRate),
		rx:   &rx,
		tx:   &tx,
	}
	return v
}

func MakeUnlimitedValve() *Valve {
	var rx, tx int64
	v := &Valve{
		rxtb: ratelimit.NewUnlimitedBucket(),
		txtb: ratelimit.NewUnlimitedBucket(),
		rx:   &rx,
		tx:   &tx,
	}
	return v
}

var UNLIMITED_VALVE = MakeUnlimitedValve()

func (v *Valve) rxWait(n int)  { v.rxtb.Wait(int64(n)) }
func (v *Valve) txWait(n int)  { v.txtb.Wait(int64(n)) }
func (v *Valve) AddRx(n int64) { atomic.AddInt64(v.rx, n) }
func (v *Valve) AddTx(n int64) { atomic.AddInt64(v.tx, n) }
func (v *Valve) GetRx() int64  { return atomic.LoadInt64(v.rx) }
func (v *Valve) GetTx() int64  { return atomic.LoadInt64(v.tx) }
func (v *Valve) Nullify() (int64, int64) {
	rx := atomic.SwapInt64(v.rx, 0)
	tx := atomic.SwapInt64(v.tx, 0)
	return rx, tx
}
