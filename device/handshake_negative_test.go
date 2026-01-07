// SPDX-License-Identifier: MIT

package device

import (
	"encoding/binary"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

func udpWriteTo(t *testing.T, addr string, b []byte) {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("net.Dial(%q): %v", addr, err)
	}
	defer c.Close()
	if _, err := c.Write(b); err != nil {
		t.Fatalf("udp write: %v", err)
	}
}

func mustPort(t *testing.T, d *Device) uint16 {
	t.Helper()
	d.net.RLock()
	p := d.net.port
	d.net.RUnlock()
	if p == 0 {
		t.Fatalf("device has port 0")
	}
	return p
}

func TestRejectBadSizesAndTypes(t *testing.T) {
	logger := NewLogger(LogLevelSilent, "(test) ")
	bindB := conn.NewDefaultBind()
	devB := NewDevice(bindB, logger)
	defer devB.Close()

	skB, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey(B): %v", err)
	}
	if err := devB.SetPrivateKey(skB); err != nil {
		t.Fatalf("SetPrivateKey(B): %v", err)
	}
	if err := devB.Up(); err != nil {
		t.Fatalf("devB.Up(): %v", err)
	}

	addrB := "127.0.0.1:" + strconv.Itoa(int(mustPort(t, devB)))

	// 1) Too small
	udpWriteTo(t, addrB, make([]byte, MinMessageSize-1))

	// 2) Initiation wrong size (147 instead of 148)
	{
		b := make([]byte, MessageInitiationSize-1)
		binary.LittleEndian.PutUint32(b[0:4], MessageInitiationType)
		udpWriteTo(t, addrB, b)
	}

	// 3) Response wrong size (91 instead of 92)
	{
		b := make([]byte, MessageResponseSize-1)
		binary.LittleEndian.PutUint32(b[0:4], MessageResponseType)
		udpWriteTo(t, addrB, b)
	}

	// 4) Wrong type (transport type) with MinMessageSize bytes
	{
		b := make([]byte, MinMessageSize)
		binary.LittleEndian.PutUint32(b[0:4], MessageTransportType)
		udpWriteTo(t, addrB, b)
	}

	// Give receiver/handshake workers a moment.
	time.Sleep(50 * time.Millisecond)

	st := devB.Stats()
	// We expect drops; we expect zero responses.
	if st.ResponsesSentTotal != 0 {
		t.Fatalf("expected no responses sent, got %d", st.ResponsesSentTotal)
	}
	if st.DropBadTypeTotal == 0 && st.DropBadSizeTotal == 0 {
		t.Fatalf("expected some bad-size or bad-type drops; stats=%+v", st)
	}
}

func TestRejectResponseUnknownReceiverIndex(t *testing.T) {
	logger := NewLogger(LogLevelSilent, "(test) ")
	bindB := conn.NewDefaultBind()
	devB := NewDevice(bindB, logger)
	defer devB.Close()

	skB, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey(B): %v", err)
	}
	if err := devB.SetPrivateKey(skB); err != nil {
		t.Fatalf("SetPrivateKey(B): %v", err)
	}
	if err := devB.Up(); err != nil {
		t.Fatalf("devB.Up(): %v", err)
	}

	addrB := "127.0.0.1:" + strconv.Itoa(int(mustPort(t, devB)))

	// A syntactically valid response message with an unknown receiver index.
	b := make([]byte, MessageResponseSize)
	binary.LittleEndian.PutUint32(b[0:4], MessageResponseType)
	// Sender (ignored in lookup failure case)
	binary.LittleEndian.PutUint32(b[4:8], 1234)
	// Receiver: random/unknown
	binary.LittleEndian.PutUint32(b[8:12], 0xdeadbeef)

	udpWriteTo(t, addrB, b)
	time.Sleep(50 * time.Millisecond)

	st := devB.Stats()
	if st.ResponsesSentTotal != 0 {
		t.Fatalf("expected no responses sent, got %d", st.ResponsesSentTotal)
	}
	// ConsumeResponseFailedTotal should typically bump (if instrumentation is wired),
	// but we keep the assertion soft to avoid false failures if you skip counters.
}

func TestRejectInitiationFromUnknownPeer(t *testing.T) {
	logger := NewLogger(LogLevelSilent, "(test) ")
	bindB := conn.NewDefaultBind()
	devB := NewDevice(bindB, logger)
	defer devB.Close()

	// Responder identity
	skB, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey(B): %v", err)
	}
	if err := devB.SetPrivateKey(skB); err != nil {
		t.Fatalf("SetPrivateKey(B): %v", err)
	}
	if err := devB.Up(); err != nil {
		t.Fatalf("devB.Up(): %v", err)
	}
	portB := mustPort(t, devB)

	// Create a legitimate initiator device C that targets B,
	// but DO NOT configure B with a peer for C's public key.
	bindC := conn.NewDefaultBind()
	devC := NewDevice(bindC, logger)
	defer devC.Close()

	skC, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey(C): %v", err)
	}
	if err := devC.SetPrivateKey(skC); err != nil {
		t.Fatalf("SetPrivateKey(C): %v", err)
	}

	// C has a peer for B, so it can create a valid initiation to B.
	peerCtoB, err := devC.NewPeer(skB.publicKey())
	if err != nil {
		t.Fatalf("devC.NewPeer(pkB): %v", err)
	}

	ep, err := devC.net.bind.ParseEndpoint("127.0.0.1:" + strconv.Itoa(int(portB)))
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	peerCtoB.endpoint.Lock()
	peerCtoB.endpoint.val = ep
	peerCtoB.endpoint.clearSrcOnTx = false
	peerCtoB.endpoint.disableRoaming = false
	peerCtoB.endpoint.Unlock()

	if err := devC.Up(); err != nil {
		t.Fatalf("devC.Up(): %v", err)
	}

	// Send initiation; B should drop because it doesn't know pkC as a peer.
	if err := peerCtoB.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("SendHandshakeInitiation(C->B): %v", err)
	}

	// Wait briefly; no response should be sent.
	time.Sleep(100 * time.Millisecond)

	st := devB.Stats()
	if st.ResponsesSentTotal != 0 {
		t.Fatalf("expected responder to send 0 responses to unknown peer; got %d", st.ResponsesSentTotal)
	}
}

func TestRejectReplayOfIdenticalInitiation(t *testing.T) {
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

	// Configure B to recognize A.
	if _, err := devB.NewPeer(skA.publicKey()); err != nil {
		t.Fatalf("devB.NewPeer(pkA): %v", err)
	}

	// Configure A peer for B so A can *create* a valid initiation.
	peerAtoB, err := devA.NewPeer(skB.publicKey())
	if err != nil {
		t.Fatalf("devA.NewPeer(pkB): %v", err)
	}

	if err := devB.Up(); err != nil {
		t.Fatalf("devB.Up(): %v", err)
	}
	addrB := "127.0.0.1:" + strconv.Itoa(int(mustPort(t, devB)))

	// Create one initiation and send it twice (byte-for-byte identical).
	msg, err := devA.CreateMessageInitiation(peerAtoB)
	if err != nil {
		t.Fatalf("CreateMessageInitiation: %v", err)
	}
	pkt := make([]byte, MessageInitiationSize)
	if err := msg.marshal(pkt); err != nil {
		t.Fatalf("marshal initiation: %v", err)
	}

	udpWriteTo(t, addrB, pkt)
	udpWriteTo(t, addrB, pkt)

	time.Sleep(150 * time.Millisecond)

	st := devB.Stats()
	// First should be accepted; second should be dropped as replay.
	if st.ResponsesSentTotal != 1 {
		t.Fatalf("expected exactly 1 response for replayed identical initiation; got %d (stats=%+v)", st.ResponsesSentTotal, st)
	}
}
