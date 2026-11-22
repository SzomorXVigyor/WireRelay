package main

import (
	"os/exec"
	"strconv"
	"strings"
	"time"

	pb "SzomorXVigyor/WireRelay/proto/wirerelay/v1"
)

const (
	connectedThresholdSeconds = 180
	degradedThresholdSeconds  = 300
)

type handshakeReport struct {
	status       pb.TunnelStatus
	state        pb.HandshakeState
	ageSeconds   int64
	errorMessage string
	peers        []*pb.PeerHealth
}

func stateSeverity(st pb.HandshakeState) int {
	switch st {
	case pb.HandshakeState_HANDSHAKE_STATE_CONNECTED:
		return 1
	case pb.HandshakeState_HANDSHAKE_STATE_DEGRADED:
		return 2
	case pb.HandshakeState_HANDSHAKE_STATE_STALE:
		return 3
	case pb.HandshakeState_HANDSHAKE_STATE_NEVER_HANDSHAKED:
		return 4
	case pb.HandshakeState_HANDSHAKE_STATE_INTERFACE_ERROR:
		return 5
	default:
		return 5
	}
}

func stateToTunnelStatus(st pb.HandshakeState) pb.TunnelStatus {
	switch st {
	case pb.HandshakeState_HANDSHAKE_STATE_CONNECTED:
		return pb.TunnelStatus_TUNNEL_STATUS_CONNECTED
	case pb.HandshakeState_HANDSHAKE_STATE_DEGRADED:
		return pb.TunnelStatus_TUNNEL_STATUS_DEGRADED
	default:
		return pb.TunnelStatus_TUNNEL_STATUS_DISCONNECTED
	}
}

// parseLatestHandshakes parses the output of `wg show <iface> latest-handshakes`.
// It reports per-peer health and derives the interface-level state from the WORST
// peer so a dead peer in a multi-peer config can never be masked by a live one.
func parseLatestHandshakes(output string, nowUnix int64) handshakeReport {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var peers []*pb.PeerHealth

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pubKey := fields[0]
		ts, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}

		if ts == 0 {
			peers = append(peers, &pb.PeerHealth{
				PublicKey:           pubKey,
				HandshakeAgeSeconds: -1,
				State:               pb.HandshakeState_HANDSHAKE_STATE_NEVER_HANDSHAKED,
			})
			continue
		}

		age := nowUnix - ts
		if age < 0 {
			age = 0
		}

		var pState pb.HandshakeState
		switch {
		case age <= connectedThresholdSeconds:
			pState = pb.HandshakeState_HANDSHAKE_STATE_CONNECTED
		case age <= degradedThresholdSeconds:
			pState = pb.HandshakeState_HANDSHAKE_STATE_DEGRADED
		default:
			pState = pb.HandshakeState_HANDSHAKE_STATE_STALE
		}

		peers = append(peers, &pb.PeerHealth{
			PublicKey:           pubKey,
			HandshakeAgeSeconds: age,
			State:               pState,
		})
	}

	if len(peers) == 0 {
		return handshakeReport{
			status:     pb.TunnelStatus_TUNNEL_STATUS_DISCONNECTED,
			state:      pb.HandshakeState_HANDSHAKE_STATE_NEVER_HANDSHAKED,
			ageSeconds: -1,
		}
	}

	worstState := pb.HandshakeState_HANDSHAKE_STATE_CONNECTED
	var worstAge int64 = 0
	hasNever := false

	for _, p := range peers {
		if stateSeverity(p.State) > stateSeverity(worstState) {
			worstState = p.State
		}
		if p.HandshakeAgeSeconds < 0 {
			hasNever = true
		} else if p.HandshakeAgeSeconds > worstAge {
			worstAge = p.HandshakeAgeSeconds
		}
	}

	if hasNever {
		worstAge = -1
	}

	return handshakeReport{
		status:     stateToTunnelStatus(worstState),
		state:      worstState,
		ageSeconds: worstAge,
		peers:      peers,
	}
}

func inspectWireGuardHandshake(iface string) handshakeReport {
	out, err := exec.Command("wg", "show", iface, "latest-handshakes").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return handshakeReport{
			status:       pb.TunnelStatus_TUNNEL_STATUS_DISCONNECTED,
			state:        pb.HandshakeState_HANDSHAKE_STATE_INTERFACE_ERROR,
			ageSeconds:   -1,
			errorMessage: msg,
		}
	}

	return parseLatestHandshakes(string(out), time.Now().Unix())
}
