// SPDX-License-Identifier: MIT

package device

import (
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

type pair struct {
	A, B      *Device
	AtoB, BtoA *Peer
}

func newDeviceWithKey(t *testing.T, logger *Logger) (*Device, NoisePrivateKey) {
	t.Helper()
	d := NewDevice(conn.NewDefaultBind(), logger)
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey: %v", err)
	}
	if err := d.SetPrivateKey(sk); err != nil {
		t.Fatalf("SetPrivateKey: %v", err)
	}
	return d, sk
}

func upAndPort(t *testing.T, d *Device) uint16 {
	t.Helper()
	if err := d.Up(); err != nil {
		t.Fatalf("Up(): %v", err)
	}
	d.net.RLock()
	p := d.net.port
	d.net.RUnlock()
	if p == 0 {
		t.Fatalf("port is 0 after Up()")
	}
	return p
}

func TestHandshakeManyInstancesManyPorts(t *testing.T) {
	// Create N independent A/B pairs, each pair on its own ports, and ensure
	// all handshakes complete concurrently.
	logger := NewLogger(LogLevelSilent, "(test) ")

	const pairsN = 20

	pairs := make([]pair, 0, pairsN)
	defer func() {
		for _, p := range pairs {
			if p.A != nil {
				p.A.Close()
			}
			if p.B != nil {
				p.B.Close()
			}
		}
	}()

	for i := 0; i < pairsN; i++ {
		devA, skA := newDeviceWithKey(t, logger)
		devB, skB := newDeviceWithKey(t, logger)

		peerAtoB, err := devA.NewPeer(skB.publicKey())
		if err != nil {
			t.Fatalf("pair %d devA.NewPeer: %v", i, err)
		}
		peerBtoA, err := devB.NewPeer(skA.publicKey())
		if err != nil {
			t.Fatalf("pair %d devB.NewPeer: %v", i, err)
		}

		// Bring up B first so A can set endpoint.
		portB := upAndPort(t, devB)
		_ = upAndPort(t, devA)

		addrB := "127.0.0.1:" + strconv.Itoa(int(portB))
		ep, err := devA.net.bind.ParseEndpoint(addrB)
		if err != nil {
			t.Fatalf("pair %d ParseEndpoint: %v", i, err)
		}
		setPeerEndpoint(peerAtoB, ep)

		pairs = append(pairs, pair{A: devA, B: devB, AtoB: peerAtoB, BtoA: peerBtoA})
	}

	var wg sync.WaitGroup
	wg.Add(len(pairs))

	for i := range pairs {
		i := i
		go func() {
			defer wg.Done()
			if err := pairs[i].AtoB.SendHandshakeInitiation(false); err != nil {
				t.Errorf("pair %d SendHandshakeInitiation: %v", i, err)
				return
			}
			waitForHandshake(t, pairs[i].AtoB, pairs[i].BtoA, 2*time.Second)
		}()
	}

	wg.Wait()

	// Spot-check: every A has a current keypair.
	for i, p := range pairs {
		if p.AtoB.keypairs.Current() == nil {
			t.Fatalf("pair %d: expected A current keypair", i)
		}
	}
}

func TestHandshakeCrossTalkIsRejected(t *testing.T) {
	// Ensure one pair's responder does not respond to an initiation from another pair
	// (unknown peer).
	logger := NewLogger(LogLevelSilent, "(test) ")

	// Pair 1
	A1, skA1 := newDeviceWithKey(t, logger)
	B1, skB1 := newDeviceWithKey(t, logger)
	defer A1.Close()
	defer B1.Close()

	A1toB1, err := A1.NewPeer(skB1.publicKey())
	if err != nil {
		t.Fatalf("A1.NewPeer: %v", err)
	}
	if _, err := B1.NewPeer(skA1.publicKey()); err != nil {
		t.Fatalf("B1.NewPeer(A1): %v", err)
	}

	// Pair 2
	A2, skA2 := newDeviceWithKey(t, logger)
	B2, skB2 := newDeviceWithKey(t, logger)
	defer A2.Close()
	defer B2.Close()

	A2toB2, err := A2.NewPeer(skB2.publicKey())
	if err != nil {
		t.Fatalf("A2.NewPeer: %v", err)
	}
	if _, err := B2.NewPeer(skA2.publicKey()); err != nil {
		t.Fatalf("B2.NewPeer(A2): %v", err)
	}

	// Bring up B1 and B2 first.
	portB1 := upAndPort(t, B1)
	portB2 := upAndPort(t, B2)
	_ = upAndPort(t, A1)
	_ = upAndPort(t, A2)

	// Correct endpoints
	epB1, err := A1.net.bind.ParseEndpoint("127.0.0.1:" + strconv.Itoa(int(portB1)))
	if err != nil {
		t.Fatalf("ParseEndpoint B1: %v", err)
	}
	setPeerEndpoint(A1toB1, epB1)

	epB2, err := A2.net.bind.ParseEndpoint("127.0.0.1:" + strconv.Itoa(int(portB2)))
	if err != nil {
		t.Fatalf("ParseEndpoint B2: %v", err)
	}
	setPeerEndpoint(A2toB2, epB2)

	// First establish both correct handshakes.
	if err := A1toB1.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("A1->B1 initiation: %v", err)
	}
	waitForHandshake(t, A1toB1, B1.LookupPeer(skA1.publicKey()), 2*time.Second) // B1 peer exists

	if err := A2toB2.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("A2->B2 initiation: %v", err)
	}
	waitForHandshake(t, A2toB2, B2.LookupPeer(skA2.publicKey()), 2*time.Second)

	// Now attempt cross-talk: A1 sends an initiation to B2's port.
	// B2 should NOT respond because it doesn't have a peer for A1.
	before := B2.Stats().ResponsesSentTotal

	epB2Wrong, err := A1.net.bind.ParseEndpoint("127.0.0.1:" + strconv.Itoa(int(portB2)))
	if err != nil {
		t.Fatalf("ParseEndpoint B2Wrong: %v", err)
	}
	setPeerEndpoint(A1toB1, epB2Wrong)

	if err := A1toB1.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("A1->B2 initiation: %v", err)
	}

	time.Sleep(120 * time.Millisecond)

	after := B2.Stats().ResponsesSentTotal
	if after != before {
		t.Fatalf("expected B2 not to respond to unknown peer (A1). responses before=%d after=%d", before, after)
	}

	// Restore endpoint for cleanliness (not required).
	_ = epB1
	fmt.Sprintf("") // keep imports stable if you adjust this file later
}
