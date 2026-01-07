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

// waitForNewHandshake waits until (a) the responder has sent one more response,
// and (b) the initiator has rotated to a new current keypair (pointer changed).
func waitForNewHandshake(t *testing.T, devResponder *Device, initiator *Peer, beforeKP *Keypair, beforeResponses uint64, timeout time.Duration) {
	t.Helper()

	ok := waitUntil(timeout, func() bool {
		afterResponses := devResponder.Stats().ResponsesSentTotal
		afterKP := initiator.keypairs.Current()
		return afterResponses > beforeResponses && afterKP != nil && afterKP != beforeKP
	})

	if !ok {
		after := devResponder.Stats()
		cur := initiator.keypairs.Current()
		t.Fatalf("handshake did not advance: responses before=%d after=%d, kp before=%p after=%p",
			beforeResponses, after.ResponsesSentTotal, beforeKP, cur)
	}
}

func TestHandshakeRepeatabilitySinglePair(t *testing.T) {
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
	_, err = devB.NewPeer(skA.publicKey())
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

	for i := 0; i < rounds; i++ {
		beforeKP := peerAtoB.keypairs.Current()
		beforeResponses := devB.Stats().ResponsesSentTotal

		if err := peerAtoB.SendHandshakeInitiation(false); err != nil {
			t.Fatalf("round %d SendHandshakeInitiation: %v", i, err)
		}

		waitForNewHandshake(t, devB, peerAtoB, beforeKP, beforeResponses, 2*time.Second)

		ka := peerAtoB.keypairs.Current()
		if ka == nil {
			t.Fatalf("round %d: expected A current keypair", i)
		}
		if !ka.isInitiator {
			t.Fatalf("round %d: expected A keypair isInitiator=true", i)
		}
	}

	stA := devA.Stats()
	stB := devB.Stats()

	if stA.InitiationsSentTotal < rounds {
		t.Fatalf("expected initiations sent >= %d; got %d (stats=%+v)", rounds, stA.InitiationsSentTotal, stA)
	}
	if stB.ResponsesSentTotal < rounds {
		t.Fatalf("expected responses sent >= %d; got %d (stats=%+v)", rounds, stB.ResponsesSentTotal, stB)
	}
}

func TestHandshakeRepeatabilityParallelInitiations(t *testing.T) {
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
	_, err = devB.NewPeer(skA.publicKey())
	if err != nil {
		t.Fatalf("devB.NewPeer(pkA): %v", err)
	}

	if err := devA.Up(); err != nil {
		t.Fatalf("devA.Up(): %v", err)
	}
	if err := devB.Up(); err != nil {
		t.Fatalf("devB.Up(): %v", err)
	}

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

	beforeKP := peerAtoB.keypairs.Current()
	beforeResponses := devB.Stats().ResponsesSentTotal

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

	// At least one handshake must advance.
	waitForNewHandshake(t, devB, peerAtoB, beforeKP, beforeResponses, 2*time.Second)

	if peerAtoB.keypairs.Current() == nil {
		t.Fatalf("expected A to have current keypair after parallel initiations")
	}
}
