// SPDX-License-Identifier: MIT
//
// Minimal tai64n implementation sufficient for wireguard handshake timestamp + replay checks.

package tai64n

import (
	"bytes"
	"encoding/binary"
	"time"
)

const TimestampSize = 12

type Timestamp [TimestampSize]byte

func Now() Timestamp {
	var ts Timestamp
	sec := uint64(time.Now().Unix())
	sec += 1 << 62 // TAI64 offset
	binary.BigEndian.PutUint64(ts[0:8], sec)
	binary.BigEndian.PutUint32(ts[8:12], uint32(time.Now().Nanosecond()))
	return ts
}

func (t Timestamp) After(u Timestamp) bool {
	return bytes.Compare(t[:], u[:]) > 0
}
