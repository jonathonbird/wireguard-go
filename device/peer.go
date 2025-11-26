/* SPDX-License-Identifier: MIT
 *
 * Stripped-down Peer implementation for handshake-only WireGuard engine
 * Derived from upstream wireguard-go with all data-plane, timer, and queue
 * logic removed.
 */

package device

import (
	"errors"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
)

type Peer struct {
	isRunning atomic.Bool
	keypairs  Keypairs
	handshake Handshake
	device    *Device

	endpoint struct {
		sync.Mutex
		val            conn.Endpoint
		clearSrcOnTx   bool
		disableRoaming bool
	}
}

func (device *Device) NewPeer(pk NoisePublicKey) (*Peer, error) {
	// Lock identity for DH pre-computation
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	device.peers.Lock()
	defer device.peers.Unlock()

	// Prevent duplicate peers
	if _, ok := device.peers.keyMap[pk]; ok {
		return nil, errors.New("adding existing peer")
	}

	peer := new(Peer)
	peer.device = device

	// Pre-compute static-static shared secret
	handshake := &peer.handshake
	handshake.mutex.Lock()
	handshake.remoteStatic = pk
	handshake.precomputedStaticStatic, _ = device.staticIdentity.privateKey.sharedSecret(pk)
	handshake.mutex.Unlock()

	// Reset endpoint
	peer.endpoint.Lock()
	peer.endpoint.val = nil
	peer.endpoint.disableRoaming = false
	peer.endpoint.clearSrcOnTx = false
	peer.endpoint.Unlock()

	// Mark running (no Start() routine in handshake-only engine)
	peer.isRunning.Store(true)

	// Add to device peer map
	device.peers.keyMap[pk] = peer

	return peer, nil
}

func (peer *Peer) SendBuffers(buffers [][]byte) error {
	peer.device.net.RLock()
	defer peer.device.net.RUnlock()

	if peer.device.net.bind == nil {
		return errors.New("device has no UDP bind")
	}

	peer.endpoint.Lock()
	endpoint := peer.endpoint.val
	if endpoint == nil {
		peer.endpoint.Unlock()
		return errors.New("no known endpoint for peer")
	}
	if peer.endpoint.clearSrcOnTx {
		endpoint.ClearSrc()
		peer.endpoint.clearSrcOnTx = false
	}
	peer.endpoint.Unlock()

	return peer.device.net.bind.Send(buffers, endpoint)
}

func (peer *Peer) String() string {
	src := peer.handshake.remoteStatic

	b64 := func(input byte) byte {
		return input + 'A' +
			byte(((25-int(input))>>8)&6) -
			byte(((51-int(input))>>8)&75) -
			byte(((61-int(input))>>8)&15) +
			byte(((62-int(input))>>8)&3)
	}

	b := []byte("peer(____…____)")
	const first = len("peer(")
	const second = len("peer(____…")

	b[first+0] = b64((src[0] >> 2) & 63)
	b[first+1] = b64(((src[0] << 4) | (src[1] >> 4)) & 63)
	b[first+2] = b64(((src[1] << 2) | (src[2] >> 6)) & 63)
	b[first+3] = b64(src[2] & 63)

	b[second+0] = b64(src[29] & 63)
	b[second+1] = b64((src[30] >> 2) & 63)
	b[second+2] = b64(((src[30] << 4) | (src[31] >> 4)) & 63)
	b[second+3] = b64((src[31] << 2) & 63)

	return string(b)
}

func (peer *Peer) SetEndpointFromPacket(endpoint conn.Endpoint) {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()

	if peer.endpoint.disableRoaming {
		return
	}

	peer.endpoint.clearSrcOnTx = false
	peer.endpoint.val = endpoint
}
