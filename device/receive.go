// SPDX-License-Identifier: MIT
//
// Handshake-only receive path for the stripped WireGuard engine.
// We keep just enough of the original receive pipeline to preserve
// intra-handshake timing and concurrency behaviour, but drop all
// transport / TUN / decryption logic.

package device

import (
	"encoding/binary"
	"errors"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// QueueHandshakeElement is a single handshake-related packet
// waiting to be processed by RoutineHandshake.
type QueueHandshakeElement struct {
	msgType  uint32
	packet   []byte
	endpoint conn.Endpoint
	// buffer is the backing storage for packet, obtained from the
	// Device message buffer pool. RoutineHandshake returns it via
	// PutMessageBuffer once processing is done.
	buffer *[MaxMessageSize]byte
}

/*
RoutineReceiveIncoming receives UDP datagrams for the Device and
dispatches just the *handshake* packets into device.queue.handshake.

Compared to upstream wireguard-go, we:

  - keep batching, error handling, and the overall goroutine structure;
  - drop all MessageTransportType handling, inbound queues, and decryption;
  - only accept MessageInitiationType and MessageResponseType (handshakes).

This preserves the same concurrency / scheduling behaviour for handshakes
while removing the transport data path.
*/
func (device *Device) RoutineReceiveIncoming(maxBatchSize int, recv conn.ReceiveFunc) {
	recvName := recv.PrettyName()
	device.log.Verbosef("Routine: receive incoming %s - started", recvName)
	defer func() {
		device.log.Verbosef("Routine: receive incoming %s - stopped", recvName)
		// One writer reference is released when this goroutine exits.
		device.queue.handshake.wg.Done()
	}()

	// Pre-allocate buffers for batched receive.
	var (
		bufsArrs  = make([]*[MaxMessageSize]byte, maxBatchSize)
		bufs      = make([][]byte, maxBatchSize)
		sizes     = make([]int, maxBatchSize)
		endpoints = make([]conn.Endpoint, maxBatchSize)
	)

	for i := range bufsArrs {
		bufsArrs[i] = device.GetMessageBuffer()
		bufs[i] = bufsArrs[i][:]
	}

	// On exit, return any unused buffers to the pool.
	defer func() {
		for i := 0; i < maxBatchSize; i++ {
			if bufsArrs[i] != nil {
				device.PutMessageBuffer(bufsArrs[i])
			}
		}
	}()

	deathSpiral := 0

	for {
		count, err := recv(bufs, sizes, endpoints)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				// Bind was closed; normal shutdown.
				return
			}
			device.log.Verbosef("Failed to receive %s packet: %v", recvName, err)
			if neterr, ok := err.(net.Error); ok && !neterr.Temporary() {
				// Permanent error: stop this receiver.
				return
			}
			if deathSpiral < 10 {
				deathSpiral++
				time.Sleep(time.Second / 3)
				continue
			}
			return
		}
		deathSpiral = 0

		// Handle each packet in the batch.
		for i, size := range sizes[:count] {
			if size < MinMessageSize {
				continue
			}

			packet := bufsArrs[i][:size]
			msgType := binary.LittleEndian.Uint32(packet[:4])

			switch msgType {

			case MessageInitiationType:
				if len(packet) != MessageInitiationSize {
					continue
				}

			case MessageResponseType:
				if len(packet) != MessageResponseSize {
					continue
				}

			default:
				// We are a handshake-only engine: drop transport,
				// cookie replies, and any unknown types.
				device.log.Verbosef("Received non-handshake packet (type %d); dropping", msgType)
				continue
			}

			// Enqueue for handshake processing. If the queue is full,
			// we silently drop (same behaviour as upstream).
			select {
			case device.queue.handshake.c <- QueueHandshakeElement{
				msgType:  msgType,
				packet:   packet,
				endpoint: endpoints[i],
				buffer:   bufsArrs[i],
			}:
				// Replace this slot with a fresh buffer from the pool.
				bufsArrs[i] = device.GetMessageBuffer()
				bufs[i] = bufsArrs[i][:]
			default:
				// Handshake queue full: drop packet.
			}
		}
	}
}

/*
RoutineHandshake handles incoming handshake-related packets.

Compared to upstream wireguard-go, we:

  - drop cookie reply handling (MessageCookieReplyType),
    ratelimiting, MAC1/MAC2 checks and cookie replies;
  - drop all timer updates, rxBytes accounting, and keepalive sending;
  - keep the sequencing of:
      - unmarshal → ConsumeMessageInitiation → SendHandshakeResponse
      - unmarshal → ConsumeMessageResponse → BeginSymmetricSession

This preserves the logical and concurrency timing of the handshake
state machine, minus DoS/cookie machinery.
*/
func (device *Device) RoutineHandshake(id int) {
	device.log.Verbosef("Routine: handshake worker %d - started", id)
	defer func() {
		device.log.Verbosef("Routine: handshake worker %d - stopped", id)
		// In the full implementation this worker also held a reference
		// on the encryption queue. In the handshake-only engine there
		// is no encryption queue to account for.
	}()

	for elem := range device.queue.handshake.c {
		switch elem.msgType {

		case MessageInitiationType:
			// Unmarshal initiation.
			var msg MessageInitiation
			if err := msg.unmarshal(elem.packet); err != nil {
				device.log.Errorf("Failed to decode initiation message: %v", err)
				device.PutMessageBuffer(elem.buffer)
				continue
			}

			// Consume initiation → get Peer.
			peer := device.ConsumeMessageInitiation(&msg)
			if peer == nil {
				device.log.Verbosef("Received invalid initiation message from %s", elem.endpoint.DstToString())
				device.PutMessageBuffer(elem.buffer)
				continue
			}

			// Update endpoint and respond.
			peer.SetEndpointFromPacket(elem.endpoint)
			device.log.Verbosef("%v - Received handshake initiation", peer)

			if err := peer.SendHandshakeResponse(); err != nil {
				device.log.Errorf("%v - Failed to send handshake response: %v", peer, err)
			}

		case MessageResponseType:
			// Unmarshal response.
			var msg MessageResponse
			if err := msg.unmarshal(elem.packet); err != nil {
				device.log.Errorf("Failed to decode response message: %v", err)
				device.PutMessageBuffer(elem.buffer)
				continue
			}

			// Consume response → get Peer.
			peer := device.ConsumeMessageResponse(&msg)
			if peer == nil {
				device.log.Verbosef("Received invalid response message from %s", elem.endpoint.DstToString())
				device.PutMessageBuffer(elem.buffer)
				continue
			}

			// Update endpoint and derive keys.
			peer.SetEndpointFromPacket(elem.endpoint)
			device.log.Verbosef("%v - Received handshake response", peer)

			if err := peer.BeginSymmetricSession(); err != nil {
				device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
			}

		default:
			// Should not happen: we only enqueue initiation/response.
			device.log.Errorf("Invalid packet ended up in the handshake queue (type %d)", elem.msgType)
		}

		// Release the backing buffer back to the pool.
		device.PutMessageBuffer(elem.buffer)
	}
}
