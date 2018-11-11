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

	rxCredit int64
	txCredit int64
}

func MakeValve(rxRate, txRate, rxCredit, txCredit int64) *Valve {
	v := &Valve{
		rxCredit: rxCredit,
		txCredit: txCredit,
	}
	v.SetRxRate(rxRate)
	v.SetTxRate(txRate)
	return v
}

func (v *Valve) SetRxRate(rate int64) {
	v.rxtb.Store(ratelimit.NewBucketWithRate(float64(rate), rate))
}

func (v *Valve) SetTxRate(rate int64) {
	v.txtb.Store(ratelimit.NewBucketWithRate(float64(rate), rate))
}

func (v *Valve) rxWait(n int) {
	v.rxtb.Load().(*ratelimit.Bucket).Wait(int64(n))
}

func (v *Valve) txWait(n int) {
	v.txtb.Load().(*ratelimit.Bucket).Wait(int64(n))
}

func (v *Valve) GetRxCredit() int64 {
	return atomic.LoadInt64(&v.rxCredit)
}

func (v *Valve) GetTxCredit() int64 {
	return atomic.LoadInt64(&v.txCredit)
}

// n can be negative
func (v *Valve) AddRxCredit(n int64) int64 {
	return atomic.AddInt64(&v.rxCredit, n)
}

// n can be negative
func (v *Valve) AddTxCredit(n int64) int64 {
	return atomic.AddInt64(&v.txCredit, n)
}
