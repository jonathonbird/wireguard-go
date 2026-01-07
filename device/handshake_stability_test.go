// SPDX-License-Identifier: MIT

package device

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

func mustParseEndpoint(t *testing.T, d *Device, addr string) conn.Endpoint {
	t.Helper()
	ep, err := d.net.bind.ParseEndpoint(addr)
	if err != nil {
		t.Fatalf("ParseEndpoint(%q): %v", addr, err)
	}
	return ep
}

func setPeerEndpoint(peer *Peer, ep conn.Endpoint) {
	peer.endpoint.Lock()
	peer.endpoint.val = ep
	peer.endpoint.clearSrcOnTx = false
	peer.endpoint.disableRoaming = false
	peer.endpoint.Unlock()
}

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

func TestHandshakeRepeatabilitySinglePair(t *testing.T) {
	// This test repeatedly performs handshakes between one A/B pair,
	// ensuring the engine remains stable and keeps producing fresh keypairs.
	logger := NewLogger(LogLevelSilent, "(test) ")

	bindA := conn.NewDefaultBind()
	bindB := conn.NewDefaultBind()

	devA := NewDevice(bindA, logger)
	devB := NewDevice(bindB, logger)
	defer devA.Close()
	defer devB.Close()

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

	peerAtoB, err := devA.NewPeer(skB.publicKey())
	if err != nil {
		t.Fatalf("devA.NewPeer(pkB): %v", err)
	}
	peerBtoA, err := devB.NewPeer(skA.publicKey())
	if err != nil {
		t.Fatalf("devB.NewPeer(pkA): %v", err)
	}

	if err := devA.Up(); err != nil {
		t.Fatalf("devA.Up(): %v", err)
	}
	if err := devB.Up(); err != nil {
		t.Fatalf("devB.Up(): %v", err)
	}

	// Set A -> B endpoint once.
	devB.net.RLock()
	portB := devB.net.port
	devB.net.RUnlock()
	if portB == 0 {
		t.Fatalf("devB has port 0 after Up()")
	}
	addrB := "127.0.0.1:" + strconv.Itoa(int(portB))
	setPeerEndpoint(peerAtoB, mustParseEndpoint(t, devA, addrB))

	const rounds = 250

	var lastLocalIndex uint32
	var lastRemoteIndex uint32
	var sawFirst bool

	for i := 0; i < rounds; i++ {
		if err := peerAtoB.SendHandshakeInitiation(false); err != nil {
			t.Fatalf("round %d SendHandshakeInitiation: %v", i, err)
		}

		waitForHandshake(t, peerAtoB, peerBtoA, 2*time.Second)

		ka := peerAtoB.keypairs.Current()
		if ka == nil {
			t.Fatalf("round %d: expected A current keypair", i)
		}
		if !ka.isInitiator {
			t.Fatalf("round %d: expected A keypair isInitiator=true", i)
		}

		// Ensure keypairs progress (indices should typically change across handshakes).
		// It’s theoretically possible to repeat by chance, but across 250 rounds it
		// would be astronomically unlikely if NewIndexForHandshake is working.
		if sawFirst {
			if ka.localIndex == lastLocalIndex && ka.remoteIndex == lastRemoteIndex {
				t.Fatalf("round %d: keypair indices did not change (local=%d remote=%d)", i, ka.localIndex, ka.remoteIndex)
			}
		}
		lastLocalIndex = ka.localIndex
		lastRemoteIndex = ka.remoteIndex
		sawFirst = true
	}

	stA := devA.Stats()
	stB := devB.Stats()

	// Initiations should have been sent.
	if stA.InitiationsSentTotal == 0 {
		t.Fatalf("expected initiations sent > 0; got %+v", stA)
	}
	// Responder should have sent responses.
	if stB.ResponsesSentTotal == 0 {
		t.Fatalf("expected responses sent > 0; got %+v", stB)
	}
}

func TestHandshakeRepeatabilityParallelInitiations(t *testing.T) {
	// Same A/B pair, but multiple goroutines initiating concurrently to shake out
	// races in queueing/handshake state transitions.
	logger := NewLogger(LogLevelSilent, "(test) ")

	bindA := conn.NewDefaultBind()
	bindB := conn.NewDefaultBind()

	devA := NewDevice(bindA, logger)
	devB := NewDevice(bindB, logger)
	defer devA.Close()
	defer devB.Close()

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

	peerAtoB, err := devA.NewPeer(skB.publicKey())
	if err != nil {
		t.Fatalf("devA.NewPeer(pkB): %v", err)
	}
	peerBtoA, err := devB.NewPeer(skA.publicKey())
	if err != nil {
		t.Fatalf("devB.NewPeer(pkA): %v", err)
	}

	if err := devA.Up(); err != nil {
		t.Fatalf("devA.Up(): %v", err)
	}
	if err := devB.Up(); err != nil {
		t.Fatalf("devB.Up(): %v", err)
	}

	// Set A -> B endpoint once.
	devB.net.RLock()
	portB := devB.net.port
	devB.net.RUnlock()
	if portB == 0 {
		t.Fatalf("devB has port 0 after Up()")
	}
	addrB := "127.0.0.1:" + strconv.Itoa(int(portB))
	setPeerEndpoint(peerAtoB, mustParseEndpoint(t, devA, addrB))

	const goroutines = 8
	const perG = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				_ = peerAtoB.SendHandshakeInitiation(false)
			}
		}()
	}
	wg.Wait()

	// We just need at least one successful handshake completion.
	waitForHandshake(t, peerAtoB, peerBtoA, 2*time.Second)

	if peerAtoB.keypairs.Current() == nil {
		t.Fatalf("expected A to have current keypair after parallel initiations")
	}
}
