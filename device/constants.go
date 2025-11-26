package device

import "time"

const (
    // queue + buffers
    QueueHandshakeSize = 1024
    MaxSegmentSize     = (1 << 16) - 1
    MaxMessageSize      = MaxSegmentSize
    MinMessageSize      = 16
    PreallocatedBuffersPerPool = 0 // unbounded, matches upstream default
)
