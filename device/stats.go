// SPDX-License-Identifier: MIT
//
// Lightweight counters for debugging and tests. These are *best effort*
// observability; they do not affect correctness.

package device

import "sync/atomic"

type DeviceStats struct {
	RecvPacketsTotal           uint64
	RecvHandshakePacketsTotal  uint64
	EnqueueTotal               uint64
	DropQueueFullTotal         uint64
	DropBadTypeTotal           uint64
	DropBadSizeTotal           uint64
	DecodeFailedTotal          uint64
	ConsumeInitiationFailedTotal uint64
	ConsumeResponseFailedTotal   uint64
	ResponsesSentTotal         uint64
	InitiationsSentTotal       uint64
}

type deviceCounters struct {
	recvPacketsTotal            atomic.Uint64
	recvHandshakePacketsTotal   atomic.Uint64
	enqueueTotal                atomic.Uint64
	dropQueueFullTotal          atomic.Uint64
	dropBadTypeTotal            atomic.Uint64
	dropBadSizeTotal            atomic.Uint64
	decodeFailedTotal           atomic.Uint64
	consumeInitiationFailedTotal atomic.Uint64
	consumeResponseFailedTotal   atomic.Uint64
	responsesSentTotal          atomic.Uint64
	initiationsSentTotal        atomic.Uint64
}

func (d *Device) Stats() DeviceStats {
	if d == nil {
		return DeviceStats{}
	}
	c := &d.counters
	return DeviceStats{
		RecvPacketsTotal:            c.recvPacketsTotal.Load(),
		RecvHandshakePacketsTotal:   c.recvHandshakePacketsTotal.Load(),
		EnqueueTotal:                c.enqueueTotal.Load(),
		DropQueueFullTotal:          c.dropQueueFullTotal.Load(),
		DropBadTypeTotal:            c.dropBadTypeTotal.Load(),
		DropBadSizeTotal:            c.dropBadSizeTotal.Load(),
		DecodeFailedTotal:           c.decodeFailedTotal.Load(),
		ConsumeInitiationFailedTotal: c.consumeInitiationFailedTotal.Load(),
		ConsumeResponseFailedTotal:   c.consumeResponseFailedTotal.Load(),
		ResponsesSentTotal:          c.responsesSentTotal.Load(),
		InitiationsSentTotal:        c.initiationsSentTotal.Load(),
	}
}
