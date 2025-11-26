// SPDX-License-Identifier: MIT
//
// Handshake-only send path for the stripped WireGuard engine.
// We keep just enough of the original send logic to preserve
// handshake initiation/response behaviour, but drop the TUN data
// path, transport encryption pipeline, timers, and cookie machinery.

package device

// SendHandshakeInitiation creates and sends a Noise_IKpsk2 initiation message.
// The isRetry flag is kept for API compatibility but has no special effect in
// the handshake-only engine.
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
