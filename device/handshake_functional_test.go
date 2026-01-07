// SPDX-License-Identifier: MIT

package device

import (
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

func waitUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}

func TestHandshakeFunctionalLocalhost(t *testing.T) {
	// Non-nil logger: receive/handshake routines call Verbosef unconditionally.
	logger := NewLogger(LogLevelSilent, "(test) ")

	bindA := conn.NewDefaultBind()
	bindB := conn.NewDefaultBind()

	devA := NewDevice(bindA, logger)
	devB := NewDevice(bindB, logger)
	defer devA.Close()
	defer devB.Close()

	// Static identities.
	skA, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey(A): %v", err)
	}
	skB, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey(B): %v", err)
	}

	if err := devA.SetPrivateKey(skA); err != nil {
		t.Fatalf("SetPrivateKey(A): %v", err)
	}
	if err := devB.SetPrivateKey(skB); err != nil {
		t.Fatalf("SetPrivateKey(B): %v", err)
	}

	pkA := skA.publicKey()
	pkB := skB.publicKey()

	peerAtoB, err := devA.NewPeer(pkB)
	if err != nil {
		t.Fatalf("devA.NewPeer(pkB): %v", err)
	}
	peerBtoA, err := devB.NewPeer(pkA)
	if err != nil {
		t.Fatalf("devB.NewPeer(pkA): %v", err)
	}
	_ = peerBtoA // responder learns endpoint from initiation packet.

	if err := devA.Up(); err != nil {
		t.Fatalf("devA.Up(): %v", err)
	}
	if err := devB.Up(); err != nil {
		t.Fatalf("devB.Up(): %v", err)
	}

	// Read devB port (it is set by bind.Open()).
	devB.net.RLock()
	portB := devB.net.port
	devB.net.RUnlock()
	if portB == 0 {
		t.Fatalf("devB has port 0 after Up()")
	}

	// Set initiator endpoint -> responder.
	addr := "127.0.0.1:" + strconv.Itoa(int(portB))

	// NOTE: if this doesn't compile, your conn.Bind may name this differently.
	ep, err := devA.net.bind.ParseEndpoint(addr)
	if err != nil {
		t.Fatalf("ParseEndpoint(%q): %v", addr, err)
	}

	peerAtoB.endpoint.Lock()
	peerAtoB.endpoint.val = ep
	peerAtoB.endpoint.clearSrcOnTx = false
	peerAtoB.endpoint.disableRoaming = false
	peerAtoB.endpoint.Unlock()

	if err := peerAtoB.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("SendHandshakeInitiation: %v", err)
	}

	ok := waitUntil(2*time.Second, func() bool {
      // Initiator should have a current keypair after it consumes the response.
      if peerAtoB.keypairs.Current() == nil {
          return false
      }
      // Responder will have "next" until transport confirms it.
      return peerBtoA.keypairs.next.Load() != nil || peerBtoA.keypairs.Current() != nil
  })
	if !ok {
		t.Fatalf("handshake did not complete: A current=%v, B current=%v, B next=%v",
        peerAtoB.keypairs.Current() != nil,
        peerBtoA.keypairs.Current() != nil,
        peerBtoA.keypairs.next.Load() != nil,
    )
	}

	ka := peerAtoB.keypairs.Current()
	if !ka.isInitiator {
		t.Fatalf("expected A-side keypair to be initiator; got isInitiator=%v", ka.isInitiator)
	}
  kn := peerBtoA.keypairs.next.Load()
  if kn == nil {
      // If current is set for some reason, fall back to current.
      kb := peerBtoA.keypairs.Current()
      if kb == nil {
          t.Fatalf("expected B-side to have next (or current) keypair, got neither")
      }
      if kb.isInitiator {
          t.Fatalf("expected B-side keypair to be responder; got isInitiator=%v", kb.isInitiator)
      }
  } else {
      if kn.isInitiator {
          t.Fatalf("expected B-side next keypair to be responder; got isInitiator=%v", kn.isInitiator)
      }
  }

}
