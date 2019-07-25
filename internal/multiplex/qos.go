package multiplex

import (
	"sync/atomic"

	"github.com/juju/ratelimit"
)

// Valve needs to be universal, across all sessions that belong to a user
// gabe please don't sue
type Valve struct {
	// traffic directions from the server's perspective are refered
	// exclusively as rx and tx.
	// rx is from client to server, tx is from server to client
	// DO NOT use terms up or down as this is used in usermanager
	// for bandwidth limiting
	rxtb atomic.Value // *ratelimit.Bucket
	txtb atomic.Value // *ratelimit.Bucket

	rx *int64
	tx *int64
}

func MakeValve(rxRate, txRate int64) *Valve {
	var rx, tx int64
	v := &Valve{
		rx: &rx,
		tx: &tx,
	}
	v.SetRxRate(rxRate)
	v.SetTxRate(txRate)
	return v
}

var UNLIMITED_VALVE = MakeValve(1<<63-1, 1<<63-1)

func (v *Valve) SetRxRate(rate int64) { v.rxtb.Store(ratelimit.NewBucketWithRate(float64(rate), rate)) }
func (v *Valve) SetTxRate(rate int64) { v.txtb.Store(ratelimit.NewBucketWithRate(float64(rate), rate)) }
func (v *Valve) rxWait(n int)         { v.rxtb.Load().(*ratelimit.Bucket).Wait(int64(n)) }
func (v *Valve) txWait(n int)         { v.txtb.Load().(*ratelimit.Bucket).Wait(int64(n)) }
func (v *Valve) AddRx(n int64)        { atomic.AddInt64(v.rx, n) }
func (v *Valve) AddTx(n int64)        { atomic.AddInt64(v.tx, n) }
func (v *Valve) GetRx() int64         { return atomic.LoadInt64(v.rx) }
func (v *Valve) GetTx() int64         { return atomic.LoadInt64(v.tx) }
func (v *Valve) Nullify() (int64, int64) {
	rx := atomic.SwapInt64(v.rx, 0)
	tx := atomic.SwapInt64(v.tx, 0)
	return rx, tx
}
