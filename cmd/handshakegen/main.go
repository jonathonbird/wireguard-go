// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	var (
		pairs     = flag.Int("pairs", 50, "number of independent A/B pairs")
		basePort  = flag.Int("base-port", 30000, "base UDP port; uses base..base+2*pairs-1")
		duration  = flag.Duration("duration", 30*time.Second, "how long to generate handshakes")
		rate      = flag.Float64("rate", 10, "handshakes per second per pair (approx)")
		jitterPct = flag.Int("jitter-pct", 20, "random +/- jitter percentage on inter-send sleep")
		verbose   = flag.Bool("v", false, "verbose logging")
	)
	flag.Parse()

	level := device.LogLevelSilent
	if *verbose {
		level = device.LogLevelVerbose
	}
	logger := device.NewLogger(level, "(handshakegen) ")

	// Ctrl-C handling
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	type pair struct {
		A, B   *device.Device
		AtoB   *device.Peer
		BtoA   *device.Peer
		portB  uint16
		closed bool
	}

	makeDev := func(listenPort uint16) *device.Device {
		b := conn.NewDefaultBind()
		d := device.NewDevice(b, logger)
		d.NetSetPortForTest(listenPort)
		return d
	}


	// NOTE:
	// wireguard-go's Bind.Open takes the requested port from bind.Open(netc.port),
	// but your stripped Device doesn't expose a setter. Easiest is to add a small
	// helper method in device (see below). If you don’t want that, you can just
	// let the OS pick ports; it still works for localhost, but you’ll have to
	// discover them and plumb endpoints.
	//
	// I’m assuming you’ll add NetSetPortForTest() as a tiny helper.

	// Create all pairs
	ps := make([]pair, 0, *pairs)

	for i := 0; i < *pairs; i++ {
		portA := uint16(*basePort + 2*i)
		portB := uint16(*basePort + 2*i + 1)

		devA := makeDev(portA)
		devB := makeDev(portB)

		skA, err := device.NewPrivateKeyForTest()
		must(err)
		skB, err := device.NewPrivateKeyForTest()
		must(err)

		must(devA.SetPrivateKey(skA))
		must(devB.SetPrivateKey(skB))

		pkA := skA.PublicKeyForTest()
		pkB := skB.PublicKeyForTest()

		peerAtoB, err := devA.NewPeer(pkB)
		must(err)
		peerBtoA, err := devB.NewPeer(pkA)
		must(err)

		_ = peerBtoA // responder learns endpoint from initiation

		must(devB.Up())
		must(devA.Up())

		// Endpoint A->B: 127.0.0.1:portB
		ep, err := devA.Bind().ParseEndpoint(net.JoinHostPort("127.0.0.1", strconv.Itoa(int(portB))))
		must(err)
		setPeerEndpoint(peerAtoB, ep)

		ps = append(ps, pair{A: devA, B: devB, AtoB: peerAtoB, BtoA: peerBtoA, portB: portB})
	}

	defer func() {
		for i := range ps {
			ps[i].A.Close()
			ps[i].B.Close()
		}
	}()

	// Handshake loop per pair
	var wg sync.WaitGroup
	wg.Add(len(ps))

	interval := time.Duration(float64(time.Second) / *rate)
	if interval < 1*time.Millisecond {
		interval = 1 * time.Millisecond
	}

	for i := range ps {
		p := ps[i]
		go func() {
			defer wg.Done()
			t0 := time.Now()
			for {
				if ctx.Err() != nil {
					return
				}
				if time.Since(t0) >= *duration {
					return
				}
				_ = p.AtoB.SendHandshakeInitiation(false)

				// jitter around interval
				j := float64(*jitterPct) / 100.0
				f := 1.0 + (rng.Float64()*2-1)*j
				sleep := time.Duration(float64(interval) * f)
				time.Sleep(sleep)
			}
		}()
	}

	wg.Wait()

	// Summary
	var totalInit, totalResp uint64
	for i := range ps {
		totalInit += ps[i].A.Stats().InitiationsSentTotal
		totalResp += ps[i].B.Stats().ResponsesSentTotal
	}
	fmt.Printf("done. pairs=%d duration=%s rate≈%.2f/s interval=%s workers=%d\n", *pairs, duration.String(), *rate, interval, runtime.NumCPU())
	fmt.Printf("initiations_sent_total=%d responses_sent_total=%d\n", totalInit, totalResp)
}

func setPeerEndpoint(peer *device.Peer, ep conn.Endpoint) {
	peer.EndpointSetForTest(ep) // see note below
}
