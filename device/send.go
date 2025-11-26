// SPDX-License-Identifier: MIT
//
// Handshake-only send path for the stripped WireGuard engine.
// We keep just enough of the original send logic to preserve
// handshake initiation/response behaviour, but drop the TUN data
// path, transport encryption pipeline, timers, and cookie machinery.

package device

import (
	"sync"
	"time"
)

/*
 * Outbound element types
 *
 * We keep these because pools.go refers to QueueOutboundElement and
 * QueueOutboundElementsContainer. They are not used by the handshake-only
 * engine at the moment, but keeping them avoids invasive changes to pools.go.
 */

type QueueOutboundElement struct {
	buffer  *[MaxMessageSize]byte // slice holding the packet data
	packet  []byte                // slice of "buffer" (always!)
	nonce   uint64                // nonce for encryption (unused in handshake-only)
	keypair *Keypair              // keypair for encryption (unused in handshake-only)
	peer    *Peer                 // related peer (unused in handshake-only)
}

type QueueOutboundElementsContainer struct {
	sync.Mutex
	elems []*QueueOutboundElement
}

// NewOutboundElement remains for compatibility with pools and potential
// future use, but is not used by the handshake-only engine.
func (device *Device) NewOutboundElement() *QueueOutboundElement {
	elem := device.GetOutboundElement()
	elem.buffer = device.GetMessageBuffer()
	elem.nonce = 0
	// keypair and peer were cleared (if necessary) by clearPointers.
	return elem
}

// clearPointers clears elem fields that contain pointers. This is used by
// PutOutboundElement in pools.go to help the GC.
func (elem *QueueOutboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.peer = nil
}

/*
 * Handshake send primitives
 *
 * These are the only pieces actually used in the handshake-only engine.
 */

// SendHandshakeInitiation creates and sends a Noise_IKpsk2 initiation message.
// The isRetry flag is kept for API compatibility but has no special effect in
// the handshake-only engine (we don't track handshakeAttempts or timers).
func (peer *Peer) SendHandshakeInitiation(isRetry bool) error {
	_ = isRetry // for API compatibility only

	peer.device.log.Verbosef("%v - Sending handshake initiation", peer)

	msg, err := peer.device.CreateMessageInitiation(peer)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to create initiation message: %v", peer, err)
		return err
	}

	packet := make([]byte, MessageInitiationSize)
	if err := msg.marshal(packet); err != nil {
		peer.device.log.Errorf("%v - Failed to marshal initiation message: %v", peer, err)
		return err
	}

	err = peer.SendBuffers([][]byte{packet})
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake initiation: %v", peer, err)
	}
	return err
}


// SendHandshakeResponse creates, finalizes, and sends a Noise_IKpsk2
// response message. It also calls BeginSymmetricSession so that the
// handshake transcript is identical to real WireGuard, even if we
// never use the resulting transport keys.
func (peer *Peer) SendHandshakeResponse() error {
	peer.device.log.Verbosef("%v - Sending handshake response", peer)

	response, err := peer.device.CreateMessageResponse(peer)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to create response message: %v", peer, err)
		return err
	}

	packet := make([]byte, MessageResponseSize)
	if err := response.marshal(packet); err != nil {
		peer.device.log.Errorf("%v - Failed to marshal response message: %v", peer, err)
		return err
	}

	if err := peer.BeginSymmetricSession(); err != nil {
		peer.device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
		return err
	}

	err = peer.SendBuffers([][]byte{packet})
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake response: %v", peer, err)
	}
	return err
}

