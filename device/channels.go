// SPDX-License-Identifier: MIT
//
// Handshake-only channel definitions for the stripped WireGuard engine.
// We keep just the handshakeQueue used by RoutineReceiveIncoming and
// RoutineHandshake, and drop all data-path queues.

package device

import "sync"

// A handshakeQueue is a channel of QueueHandshakeElement awaiting processing
// by the handshake workers (RoutineHandshake). It is ref-counted via wg:
//
//   - newHandshakeQueue starts with wg = 1.
//   - Every additional writer should call q.wg.Add(1).
//   - Every completed writer should call q.wg.Done().
//   - When no further writers will be added, the last Done() will close q.c.
//
type handshakeQueue struct {
	c  chan QueueHandshakeElement
	wg sync.WaitGroup
}

func newHandshakeQueue() *handshakeQueue {
	q := &handshakeQueue{
		c: make(chan QueueHandshakeElement, QueueHandshakeSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}
