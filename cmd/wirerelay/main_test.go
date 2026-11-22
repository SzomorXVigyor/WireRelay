package main

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "SzomorXVigyor/WireRelay/proto/wirerelay/v1"
)

func TestParseLatestHandshakes(t *testing.T) {
	now := int64(1_700_000_000)

	t.Run("no peers means never handshaked", func(t *testing.T) {
		rep := parseLatestHandshakes("", now)
		if rep.state != pb.HandshakeState_HANDSHAKE_STATE_NEVER_HANDSHAKED {
			t.Fatalf("got state %v, want NEVER_HANDSHAKED", rep.state)
		}
		if rep.ageSeconds != -1 {
			t.Fatalf("got age %d, want -1", rep.ageSeconds)
		}
	})

	t.Run("peer timestamp 0 means never handshaked", func(t *testing.T) {
		rep := parseLatestHandshakes("peerA=\t0\n", now)
		if rep.state != pb.HandshakeState_HANDSHAKE_STATE_NEVER_HANDSHAKED {
			t.Fatalf("got state %v, want NEVER_HANDSHAKED", rep.state)
		}
	})

	t.Run("single healthy peer", func(t *testing.T) {
		rep := parseLatestHandshakes("peerA=\t1699999950\n", now)
		if rep.state != pb.HandshakeState_HANDSHAKE_STATE_CONNECTED || rep.status != pb.TunnelStatus_TUNNEL_STATUS_CONNECTED {
			t.Fatalf("got (%v, %v), want CONNECTED", rep.status, rep.state)
		}
		if rep.ageSeconds != 50 {
			t.Fatalf("got age %d, want 50", rep.ageSeconds)
		}
	})

	t.Run("previously connected peer now stale", func(t *testing.T) {
		rep := parseLatestHandshakes("peerA=\t1699999500\n", now)
		if rep.state != pb.HandshakeState_HANDSHAKE_STATE_STALE || rep.status != pb.TunnelStatus_TUNNEL_STATUS_DISCONNECTED {
			t.Fatalf("got (%v, %v), want DISCONNECTED/STALE", rep.status, rep.state)
		}
		if rep.ageSeconds != 500 {
			t.Fatalf("got age %d, want 500", rep.ageSeconds)
		}
	})

	t.Run("multi-peer takes worst peer instead of masking dead peer (R8)", func(t *testing.T) {
		out := "peerGood=\t1699999990\npeerDead=\t1699999000\n"
		rep := parseLatestHandshakes(out, now)
		if rep.state != pb.HandshakeState_HANDSHAKE_STATE_STALE {
			t.Fatalf("got state %v, want STALE", rep.state)
		}
		if len(rep.peers) != 2 {
			t.Fatalf("got %d peers, want 2", len(rep.peers))
		}
	})
}

func TestParsePeerEndpoints(t *testing.T) {
	conf := `
[Interface]
PrivateKey = abc
Address = 10.0.0.2/32

[Peer]
PublicKey = pub1=
Endpoint = ddns.example.com:51820
AllowedIPs = 192.168.1.0/24

[Peer]
PublicKey = pub2=
Endpoint = 203.0.113.5:51820
AllowedIPs = 192.168.2.0/24
`
	peers := parsePeerEndpoints(conf)
	if len(peers) != 1 {
		t.Fatalf("expected 1 hostname peer (IP literal skipped), got %d", len(peers))
	}
	if peers[0].publicKey != "pub1=" || peers[0].host != "ddns.example.com" || peers[0].port != "51820" {
		t.Fatalf("unexpected parsed peer: %+v", peers[0])
	}
}

func TestTunnelStreamTargetCloseAndAuth(t *testing.T) {
	// Echo-then-close TCP target to verify R1 (TunnelClose sent on target EOF)
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetLn.Close()

	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			_, _ = conn.Write(buf[:n])
		}
		// Immediately close target after echo -> must deliver TunnelClose to gRPC client!
	}()

	// Start WireRelay gRPC server with auth token enabled (R5)
	grpcLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen grpc: %v", err)
	}
	defer grpcLn.Close()

	const token = "super-secret-runner-token"
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	defer shutdownCancel()

	gs := grpc.NewServer(
		grpc.UnaryInterceptor(unaryAuthInterceptor(token)),
		grpc.StreamInterceptor(streamAuthInterceptor(token)),
	)
	pb.RegisterWireRelayServiceServer(gs, newRelayServer(shutdownCtx, "wg0", 4))
	go func() { _ = gs.Serve(grpcLn) }()
	defer gs.Stop()

	conn, err := grpc.NewClient(grpcLn.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial grpc: %v", err)
	}
	defer conn.Close()
	client := pb.NewWireRelayServiceClient(conn)

	// 1. Missing token must fail with Unauthenticated
	_, err = client.GetHealth(context.Background(), &pb.HealthRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated without token, got %v", err)
	}

	// 2. Authenticated TunnelStream echoes and receives explicit TunnelClose on target EOF
	authCtx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
	ctx, cancel := context.WithTimeout(authCtx, 3*time.Second)
	defer cancel()

	stream, err := client.TunnelStream(ctx)
	if err != nil {
		t.Fatalf("TunnelStream: %v", err)
	}

	tAddr := targetLn.Addr().(*net.TCPAddr)
	if err := stream.Send(&pb.TunnelFrame{
		Frame: &pb.TunnelFrame_Header{
			Header: &pb.TunnelHeader{
				TargetHost: "127.0.0.1",
				TargetPort: uint32(tAddr.Port),
				Protocol:   pb.TransportProtocol_TRANSPORT_PROTOCOL_TCP,
			},
		},
	}); err != nil {
		t.Fatalf("send header: %v", err)
	}

	ackFrame, err := stream.Recv()
	if err != nil || !ackFrame.GetAck().GetSuccess() {
		t.Fatalf("expected success ack, got frame=%v err=%v", ackFrame, err)
	}

	if err := stream.Send(&pb.TunnelFrame{
		Frame: &pb.TunnelFrame_Payload{Payload: []byte("ping")},
	}); err != nil {
		t.Fatalf("send payload: %v", err)
	}

	echoFrame, err := stream.Recv()
	if err != nil || string(echoFrame.GetPayload()) != "ping" {
		t.Fatalf("expected payload 'ping', got frame=%v err=%v", echoFrame, err)
	}

	closeFrame, err := stream.Recv()
	if err != nil {
		t.Fatalf("expected TunnelClose frame before EOF, got err=%v", err)
	}
	if closeFrame.GetClose() == nil {
		t.Fatalf("expected TunnelClose frame, got %+v", closeFrame)
	}

	// Subsequent Recv should finish cleanly with io.EOF (no hang!)
	_, err = stream.Recv()
	if err != io.EOF {
		t.Fatalf("expected io.EOF after TunnelClose, got %v", err)
	}
}
