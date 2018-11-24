package multiplex

import (
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
)

// switchboard is responsible for keeping the reference of TLS connections between client and server
type switchboard struct {
	session *Session

	*Valve

	// optimum is the connEnclave with the smallest sendQueue
	optimum atomic.Value // *connEnclave
	cesM    sync.RWMutex
	ces     []*connEnclave

	/*
		//debug
		hM   sync.Mutex
		used map[uint32]bool
	*/
}

func (sb *switchboard) getOptimum() *connEnclave {
	if i := sb.optimum.Load(); i == nil {
		return nil
	} else {
		return i.(*connEnclave)
	}
}

func (sb *switchboard) setOptimum(ce *connEnclave) {
	sb.optimum.Store(ce)
}

// Some data comes from a Stream to be sent through one of the many
// remoteConn, but which remoteConn should we use to send the data?
//
// In this case, we pick the remoteConn that has about the smallest sendQueue.
type connEnclave struct {
	remoteConn net.Conn
	sendQueue  uint32
}

func makeSwitchboard(sesh *Session, valve *Valve) *switchboard {
	// rates are uint64 because in the usermanager we want the bandwidth to be atomically
	// operated (so that the bandwidth can change on the fly).
	sb := &switchboard{
		session: sesh,
		Valve:   valve,
		ces:     []*connEnclave{},
		//debug
		// used: make(map[uint32]bool),
	}
	return sb
}

var errNilOptimum error = errors.New("The optimal connection is nil")

var ErrNoRxCredit error = errors.New("No Rx credit is left")
var ErrNoTxCredit error = errors.New("No Tx credit is left")

func (sb *switchboard) send(data []byte) (int, error) {
	ce := sb.getOptimum()
	if ce == nil {
		return 0, errNilOptimum
	}
	atomic.AddUint32(&ce.sendQueue, uint32(len(data)))
	go sb.updateOptimum()
	n, err := ce.remoteConn.Write(data)
	if err != nil {
		return n, err
		// TODO
	}
	if sb.AddTxCredit(-int64(n)) < 0 {
		log.Println(ErrNoTxCredit)
		defer sb.session.Close()
		return n, ErrNoTxCredit
	}
	atomic.AddUint32(&ce.sendQueue, ^uint32(n-1))
	go sb.updateOptimum()
	return n, nil
}

func (sb *switchboard) updateOptimum() {
	currentOpti := sb.getOptimum()
	currentOptiQ := atomic.LoadUint32(&currentOpti.sendQueue)
	sb.cesM.RLock()
	for _, ce := range sb.ces {
		ceQ := atomic.LoadUint32(&ce.sendQueue)
		if ceQ < currentOptiQ {
			currentOpti = ce
			currentOptiQ = ceQ
		}
	}
	sb.cesM.RUnlock()
	sb.setOptimum(currentOpti)
}

func (sb *switchboard) addConn(conn net.Conn) {
	newCe := &connEnclave{
		remoteConn: conn,
		sendQueue:  0,
	}
	sb.cesM.Lock()
	sb.ces = append(sb.ces, newCe)
	sb.cesM.Unlock()
	sb.setOptimum(newCe)
	go sb.deplex(newCe)
}

func (sb *switchboard) removeConn(closing *connEnclave) {
	sb.cesM.Lock()
	for i, ce := range sb.ces {
		if closing == ce {
			sb.ces = append(sb.ces[:i], sb.ces[i+1:]...)
			break
		}
	}
	if len(sb.ces) == 0 {
		sb.session.Close()
	}
	sb.cesM.Unlock()
}

func (sb *switchboard) shutdown() {
	for _, ce := range sb.ces {
		ce.remoteConn.Close()
	}
}

// deplex function costantly reads from a TCP connection, call deobfs and distribute it
// to the corresponding frame
func (sb *switchboard) deplex(ce *connEnclave) {
	buf := make([]byte, 20480)
	for {
		n, err := sb.session.obfsedRead(ce.remoteConn, buf)
		sb.rxWait(n)
		if err != nil {
			log.Println(err)
			go ce.remoteConn.Close()
			sb.removeConn(ce)
			return
		}
		if sb.AddRxCredit(-int64(n)) < 0 {
			log.Println(ErrNoRxCredit)
			sb.session.Close()
			return
		}
		frame := sb.session.deobfs(buf[:n])

		// FIXME: there has been a bug in which a packet has
		// a seemingly corrupted StreamID (e.g. when the largest streamID is something like 3000
		// and suddently a streamID of 3358661675 is added.
		// It happens once ~6 hours and the occourance is realy unstable
		// I couldn't find a way to reproduce it. But I do have some clue.
		// I commented out the util.genXorKeys function so that the stream headers are being
		// sent in plaintext, and this bug didn't happen again. So I suspect it has to do
		// with xxHash. Either it's to do with my usage of the libary or the implementation
		// of the library. Maybe there's a race somewhere? I may eventually use another
		// method to encrypt the headers. xxHash isn't cryptographic afterall.

		stream := sb.session.getOrAddStream(frame.StreamID, frame.Closing == 1)
		// if the frame is telling us to close a closed stream
		// (this happens when ss-server and ss-local closes the stream
		// simutaneously), we don't do anything
		if stream != nil {
			stream.writeNewFrame(frame)
		}
		//debug
		/*
			sb.hM.Lock()
			if sb.used[frame.StreamID] {
				log.Printf("%v lost!\n", frame.StreamID)
			}
			sb.used[frame.StreamID] = true
			sb.hM.Unlock()
		*/
	}
}
