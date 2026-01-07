/* SPDX-License-Identifier: MIT
 *
 * Handshake-only Device implementation for stripped WireGuard engine.
 * Derived from upstream wireguard-go/device.go with all TUN, data-path,
 * timers, ratelimiter, and cookie machinery removed.
 */

package device

import (
	"runtime"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
	"errors"
)


type Device struct {
	state struct {
		// state holds the device's state. It is accessed atomically.
		// See deviceState docs below.
		state atomic.Uint32
		// mu protects state transitions.
		sync.Mutex
	}

	net struct {
		stopping sync.WaitGroup
		sync.RWMutex
		bind conn.Bind // UDP bind interface
		port uint16    // listening port
	}

	staticIdentity struct {
		sync.RWMutex
		privateKey NoisePrivateKey
		publicKey  NoisePublicKey
	}

	peers struct {
		sync.RWMutex // protects keyMap
		keyMap       map[NoisePublicKey]*Peer
	}

	indexTable IndexTable

	pool struct {
		messageBuffers *WaitPool
	}

	counters deviceCounters


	queue struct {
		handshake *handshakeQueue
	}

	closed chan struct{}
	log    *Logger
}

// deviceState represents the state of a Device.
// There are three states: down, up, closed.
// Transitions:
//
//	down -----+
//	  ↑↓      ↓
//	  up -> closed
type deviceState uint32

const (
	deviceStateDown deviceState = iota
	deviceStateUp
	deviceStateClosed
)

// deviceState returns device.state.state as a deviceState.
func (device *Device) deviceState() deviceState {
	return deviceState(device.state.state.Load())
}

// isClosed reports whether the device is closed (or is closing).
func (device *Device) isClosed() bool {
	return device.deviceState() == deviceStateClosed
}

// isUp reports whether the device is up (or is attempting to come up).
func (device *Device) isUp() bool {
	return device.deviceState() == deviceStateUp
}

// NewDevice constructs a new handshake-only Device.
// It does not know about TUN or any data path; only UDP bind and handshakes.
func NewDevice(bind conn.Bind, logger *Logger) *Device {
	device := new(Device)
	device.state.state.Store(uint32(deviceStateDown))
	device.closed = make(chan struct{})
	device.log = logger
	device.net.bind = bind

	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
	device.indexTable.Init()

	device.PopulatePools()

	// Create handshake queue.
	device.queue.handshake = newHandshakeQueue()

	// Start handshake workers.
	cpus := runtime.NumCPU()
	for i := 0; i < cpus; i++ {
		go device.RoutineHandshake(i + 1)
	}

	return device
}

// changeState attempts to change the device state to match want.
func (device *Device) changeState(want deviceState) (err error) {
	device.state.Lock()
	defer device.state.Unlock()
	old := device.deviceState()
	if old == deviceStateClosed {
		// once closed, always closed
		if device.log != nil {
			device.log.Verbosef("Interface closed, ignored requested state %v", want)
		}
		return nil
	}
	switch want {
	case old:
		return nil
	case deviceStateUp:
		device.state.state.Store(uint32(deviceStateUp))
		err = device.upLocked()
		if err == nil {
			break
		}
		fallthrough // up failed; bring the device back down
	case deviceStateDown:
		device.state.state.Store(uint32(deviceStateDown))
		errDown := device.downLocked()
		if err == nil {
			err = errDown
		}
	}
	if device.log != nil {
		device.log.Verbosef("Interface state was %v, requested %v, now %v", old, want, device.deviceState())
	}
	return
}

// upLocked attempts to bring the device up (open UDP bind and start receivers).
// The caller must hold device.state.mu and is responsible for updating device.state.state.
func (device *Device) upLocked() error {
	if err := device.BindUpdate(); err != nil {
		if device.log != nil {
			device.log.Errorf("Unable to update bind: %v", err)
		}
		return err
	}
	return nil
}

// downLocked attempts to bring the device down (close UDP bind).
// The caller must hold device.state.mu and is responsible for updating device.state.state.
func (device *Device) downLocked() error {
	err := device.BindClose()
	if err != nil && device.log != nil {
		device.log.Errorf("Bind close failed: %v", err)
	}
	return err
}

// Up transitions the device to the "up" state (bind open, receivers running).
func (device *Device) Up() error {
	return device.changeState(deviceStateUp)
}

// Down transitions the device to the "down" state (bind closed, no receivers).
func (device *Device) Down() error {
	return device.changeState(deviceStateDown)
}

// SetPrivateKey sets the device's static private key and computes the
// corresponding public key. In the handshake-only engine we keep this
// simple and do not support changing the private key while peers exist.
func (device *Device) SetPrivateKey(sk NoisePrivateKey) error {
	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()

	if sk.Equals(device.staticIdentity.privateKey) {
		return nil
	}

	device.peers.RLock()
	defer device.peers.RUnlock()
	if len(device.peers.keyMap) > 0 {
		// For the testbed / handshake-only engine we don't implement
		// the full peer rekey / expiration dance. Keep it explicit.
		return ErrPrivateKeyChangeWithPeers
	}

	device.staticIdentity.privateKey = sk
	device.staticIdentity.publicKey = sk.publicKey()
	return nil
}

// ErrPrivateKeyChangeWithPeers is returned when attempting to change the
// device's private key while peers already exist (unsupported in handshake-only mode).
var ErrPrivateKeyChangeWithPeers = errors.New("cannot change private key while peers exist")

// BatchSize returns the batch size for the device as a whole.
// In the handshake-only engine this is just the bind's batch size.
func (device *Device) BatchSize() int {
	device.net.RLock()
	defer device.net.RUnlock()
	if device.net.bind == nil {
		return 1
	}
	return device.net.bind.BatchSize()
}

func (device *Device) LookupPeer(pk NoisePublicKey) *Peer {
	device.peers.RLock()
	defer device.peers.RUnlock()

	return device.peers.keyMap[pk]
}

func (device *Device) RemovePeer(key NoisePublicKey) {
	device.peers.Lock()
	defer device.peers.Unlock()

	delete(device.peers.keyMap, key)
}

func (device *Device) RemoveAllPeers() {
	device.peers.Lock()
	defer device.peers.Unlock()

	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
}

// Close shuts down the device: closes the UDP bind, stops receivers,
// closes the handshake queue, and drops all peers.
func (device *Device) Close() {
	device.state.Lock()
	defer device.state.Unlock()

	if device.isClosed() {
		return
	}
	device.state.state.Store(uint32(deviceStateClosed))
	if device.log != nil {
		device.log.Verbosef("Device closing")
	}

	// Close UDP bind and wait for receive goroutines to stop.
	device.BindClose()

	// Remove peers.
	device.RemoveAllPeers()

	// Drop the initial reference on the handshake queue so it can close
	// once all receiver goroutines have exited.
	device.queue.handshake.wg.Done()

	if device.log != nil {
		device.log.Verbosef("Device closed")
	}
	close(device.closed)
}

func (device *Device) Wait() chan struct{} {
	return device.closed
}

// closeBindLocked closes the device's net.bind.
// The caller must hold the net mutex.
func closeBindLocked(device *Device) error {
	var err error
	netc := &device.net
	if netc.bind != nil {
		err = netc.bind.Close()
	}
	netc.stopping.Wait()
	return err
}

// Bind returns the current UDP bind.
func (device *Device) Bind() conn.Bind {
	device.net.RLock()
	defer device.net.RUnlock()
	return device.net.bind
}

// BindUpdate closes any existing sockets and, if the device is up,
// re-opens the bind and starts receive goroutines.
func (device *Device) BindUpdate() error {
	device.net.Lock()
	defer device.net.Unlock()

	// close existing sockets
	if err := closeBindLocked(device); err != nil {
		return err
	}

	// open new sockets only if device is up
	if !device.isUp() || device.net.bind == nil {
		return nil
	}

	var (
		err     error
		recvFns []conn.ReceiveFunc
		netc    = &device.net
	)

	recvFns, netc.port, err = netc.bind.Open(netc.port)
	if err != nil {
		netc.port = 0
		return err
	}

	// start receiving routines
	device.net.stopping.Add(len(recvFns))
	device.queue.handshake.wg.Add(len(recvFns)) // each RoutineReceiveIncoming writes to device.queue.handshake
	batchSize := netc.bind.BatchSize()
	for _, fn := range recvFns {
		go device.RoutineReceiveIncoming(batchSize, fn)
	}

	if device.log != nil {
		device.log.Verbosef("UDP bind has been updated")
	}
	return nil
}

// BindClose closes the current UDP bind and waits for all receive
// goroutines to exit.
func (device *Device) BindClose() error {
	device.net.Lock()
	err := closeBindLocked(device)
	device.net.Unlock()
	return err
}
