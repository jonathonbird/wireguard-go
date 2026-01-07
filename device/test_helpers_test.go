// SPDX-License-Identifier: MIT

package device

import (
	"testing"
	"time"
)

// waitForHandshake waits until the initiator has a current keypair and
// the responder has either next or current set (depending on timing).
func waitForHandshake(t *testing.T, aToB, bToA *Peer, timeout time.Duration) {
	t.Helper()

	ok := waitUntil(timeout, func() bool {
		if aToB.keypairs.Current() == nil {
			return false
		}
		return bToA.keypairs.next.Load() != nil || bToA.keypairs.Current() != nil
	})

	if !ok {
		t.Fatalf("handshake did not complete: A current=%v, B current=%v, B next=%v",
			aToB.keypairs.Current() != nil,
			bToA.keypairs.Current() != nil,
			bToA.keypairs.next.Load() != nil,
		)
	}
}
