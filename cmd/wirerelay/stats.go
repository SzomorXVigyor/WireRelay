package main

import (
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	pb "SzomorXVigyor/WireRelay/proto/wirerelay/v1"
)

// relayStats tracks lock-free runtime counters for TunnelStream activity and daemon uptime.
type relayStats struct {
	startedAt            time.Time
	maxStreams           uint32
	activeStreams        atomic.Int64
	dialErrorsTotal      atomic.Uint64
	streamsRejectedTotal atomic.Uint64
}

func newRelayStats(maxStreams int) *relayStats {
	if maxStreams < 1 {
		maxStreams = defaultMaxConcurrentStreams
	}
	return &relayStats{
		startedAt:  time.Now(),
		maxStreams: uint32(maxStreams),
	}
}

func (r *relayStats) UptimeSeconds() int64 {
	sec := int64(time.Since(r.startedAt).Seconds())
	if sec < 0 {
		return 0
	}
	return sec
}

func (r *relayStats) MaxStreams() uint32 {
	return r.maxStreams
}

func (r *relayStats) ActiveStreams() uint32 {
	v := r.activeStreams.Load()
	if v < 0 {
		return 0
	}
	return uint32(v)
}

func (r *relayStats) IncActiveStreams() {
	r.activeStreams.Add(1)
}

func (r *relayStats) DecActiveStreams() {
	r.activeStreams.Add(-1)
}

func (r *relayStats) IncDialErrors() {
	r.dialErrorsTotal.Add(1)
}

func (r *relayStats) DialErrorsTotal() uint64 {
	return r.dialErrorsTotal.Load()
}

func (r *relayStats) IncStreamsRejected() {
	r.streamsRejectedTotal.Add(1)
}

func (r *relayStats) StreamsRejectedTotal() uint64 {
	return r.streamsRejectedTotal.Load()
}

type transferReport struct {
	rxBytes      uint64
	txBytes      uint64
	peers        []*pb.PeerTransferStats
	errorMessage string
}

// parseTransferOutput parses `wg show <iface> transfer` lines (`<pubkey>\t<rx>\t<tx>`).
func parseTransferOutput(output string) transferReport {
	var rep transferReport
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		rx, err1 := strconv.ParseUint(fields[1], 10, 64)
		tx, err2 := strconv.ParseUint(fields[2], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		rep.rxBytes += rx
		rep.txBytes += tx
		rep.peers = append(rep.peers, &pb.PeerTransferStats{
			PublicKey: fields[0],
			RxBytes:   rx,
			TxBytes:   tx,
		})
	}
	return rep
}

func inspectWireGuardTransfer(iface string) transferReport {
	out, err := exec.Command("wg", "show", iface, "transfer").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return transferReport{errorMessage: msg}
	}
	return parseTransferOutput(string(out))
}
