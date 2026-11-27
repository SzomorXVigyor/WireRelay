package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "SzomorXVigyor/WireRelay/proto/wirerelay/v1"
)

func TestParseTransferOutput(t *testing.T) {
	t.Run("empty output", func(t *testing.T) {
		rep := parseTransferOutput("")
		if rep.rxBytes != 0 || rep.txBytes != 0 || len(rep.peers) != 0 {
			t.Fatalf("expected zero transfer report, got %+v", rep)
		}
	})

	t.Run("sums multiple peers and ignores malformed lines", func(t *testing.T) {
		raw := "peerA=\t1200\t3400\nbadline\npeerB=\t800\t600\npeerBad=\tnotanint\t10\n"
		rep := parseTransferOutput(raw)
		if rep.rxBytes != 2000 || rep.txBytes != 4000 {
			t.Fatalf("got rx=%d tx=%d, want rx=2000 tx=4000", rep.rxBytes, rep.txBytes)
		}
		if len(rep.peers) != 2 {
			t.Fatalf("expected 2 peers, got %d", len(rep.peers))
		}
		if rep.peers[0].PublicKey != "peerA=" || rep.peers[0].RxBytes != 1200 || rep.peers[0].TxBytes != 3400 {
			t.Fatalf("unexpected first peer: %+v", rep.peers[0])
		}
	})
}

func TestGetStatsGRPC(t *testing.T) {
	// Hold-open TCP target so we can observe active_streams == 1 and streams_rejected_total == 1.
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetLn.Close()

	targetRelease := make(chan struct{})
	defer close(targetRelease)
	go func() {
		for {
			conn, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				<-targetRelease
			}(conn)
		}
	}()

	// Pick an unused local port for dial error testing.
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dead port: %v", err)
	}
	deadPort := deadLn.Addr().(*net.TCPAddr).Port
	deadLn.Close()

	grpcLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen grpc: %v", err)
	}
	defer grpcLn.Close()

	const token = "stats-test-token"
	stats := newRelayStats(1) // cap=1 to test streams_rejected_total deterministically
	stats.startedAt = time.Now().Add(-15 * time.Second)

	srv := newRelayServerWithStats(context.Background(), "wg0", 1, nil, stats)
	srv.transferFn = func(iface string) transferReport {
		return transferReport{
			rxBytes: 4096,
			txBytes: 8192,
			peers: []*pb.PeerTransferStats{
				{PublicKey: "peer1=", RxBytes: 4096, TxBytes: 8192},
			},
		}
	}

	gs := grpc.NewServer(
		grpc.UnaryInterceptor(unaryAuthInterceptor(token)),
		grpc.StreamInterceptor(streamAuthInterceptor(token)),
	)
	pb.RegisterWireRelayServiceServer(gs, srv)
	go func() { _ = gs.Serve(grpcLn) }()
	defer gs.Stop()

	conn, err := grpc.NewClient(grpcLn.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial grpc: %v", err)
	}
	defer conn.Close()
	client := pb.NewWireRelayServiceClient(conn)

	// Unauthenticated call must fail.
	if _, err := client.GetStats(context.Background(), &pb.StatsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}

	authCtx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))

	// Baseline stats check.
	st, err := client.GetStats(authCtx, &pb.StatsRequest{})
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if st.GetInterface() != "wg0" || st.GetRxBytes() != 4096 || st.GetTxBytes() != 8192 {
		t.Fatalf("unexpected transfer stats: %+v", st)
	}
	if st.GetUptimeSeconds() < 14 || st.GetMaxStreams() != 1 || st.GetActiveStreams() != 0 {
		t.Fatalf("unexpected baseline runtime stats: %+v", st)
	}

	// Open stream 1 (occupies sole slot).
	s1Ctx, s1Cancel := context.WithCancel(authCtx)
	s1, err := client.TunnelStream(s1Ctx)
	if err != nil {
		t.Fatalf("open stream 1: %v", err)
	}
	tAddr := targetLn.Addr().(*net.TCPAddr)
	if err := s1.Send(&pb.TunnelFrame{
		Frame: &pb.TunnelFrame_Header{
			Header: &pb.TunnelHeader{
				TargetHost: "127.0.0.1",
				TargetPort: uint32(tAddr.Port),
				Protocol:   pb.TransportProtocol_TRANSPORT_PROTOCOL_TCP,
			},
		},
	}); err != nil {
		t.Fatalf("send header 1: %v", err)
	}
	if ack, err := s1.Recv(); err != nil || !ack.GetAck().GetSuccess() {
		t.Fatalf("expected stream 1 ack, got frame=%v err=%v", ack, err)
	}

	st, err = client.GetStats(authCtx, &pb.StatsRequest{})
	if err != nil {
		t.Fatalf("GetStats while active: %v", err)
	}
	if st.GetActiveStreams() != 1 {
		t.Fatalf("expected active_streams=1, got %d", st.GetActiveStreams())
	}

	// Open stream 2 while cap=1 is full -> must be rejected with ResourceExhausted.
	s2, err := client.TunnelStream(authCtx)
	if err != nil {
		t.Fatalf("open stream 2: %v", err)
	}
	_, err = s2.Recv()
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected ResourceExhausted for stream 2, got %v", err)
	}

	st, err = client.GetStats(authCtx, &pb.StatsRequest{})
	if err != nil {
		t.Fatalf("GetStats after rejection: %v", err)
	}
	if st.GetStreamsRejectedTotal() != 1 {
		t.Fatalf("expected streams_rejected_total=1, got %d", st.GetStreamsRejectedTotal())
	}

	// Close stream 1 and wait for active_streams to drop back to 0.
	s1Cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st, err = client.GetStats(authCtx, &pb.StatsRequest{})
		if err == nil && st.GetActiveStreams() == 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if st.GetActiveStreams() != 0 {
		t.Fatalf("expected active_streams=0 after closing stream 1, got %d", st.GetActiveStreams())
	}

	// Trigger a dial error against the closed local port.
	s3Ctx, s3Cancel := context.WithTimeout(authCtx, 3*time.Second)
	defer s3Cancel()
	s3, err := client.TunnelStream(s3Ctx)
	if err != nil {
		t.Fatalf("open stream 3: %v", err)
	}
	if err := s3.Send(&pb.TunnelFrame{
		Frame: &pb.TunnelFrame_Header{
			Header: &pb.TunnelHeader{
				TargetHost: "127.0.0.1",
				TargetPort: uint32(deadPort),
				Protocol:   pb.TransportProtocol_TRANSPORT_PROTOCOL_TCP,
				TimeoutMs:  1000,
			},
		},
	}); err != nil {
		t.Fatalf("send header 3: %v", err)
	}
	// First frame is NACK, then Unavailable error on next Recv.
	_, _ = s3.Recv()
	_, _ = s3.Recv()

	st, err = client.GetStats(authCtx, &pb.StatsRequest{})
	if err != nil {
		t.Fatalf("GetStats after dial error: %v", err)
	}
	if st.GetDialErrorsTotal() != 1 {
		t.Fatalf("expected dial_errors_total=1, got %d", st.GetDialErrorsTotal())
	}
	if st.GetActiveStreams() != 0 {
		t.Fatalf("expected active_streams=0 after dial error, got %d", st.GetActiveStreams())
	}
}

func TestRESTStatsEndpoint(t *testing.T) {
	stats := newRelayStats(64)
	stats.startedAt = time.Now().Add(-30 * time.Second)
	stats.IncActiveStreams()
	stats.IncDialErrors()
	stats.IncStreamsRejected()

	mux := newRESTMux(nil, stats, func(iface string) transferReport {
		return transferReport{
			rxBytes: 1234,
			txBytes: 5678,
			peers:   []*pb.PeerTransferStats{{PublicKey: "p1=", RxBytes: 1234, TxBytes: 5678}},
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if payload["rx_bytes"] != float64(1234) || payload["tx_bytes"] != float64(5678) {
		t.Fatalf("unexpected rx/tx bytes: %+v", payload)
	}
	if payload["active_streams"] != float64(1) || payload["max_streams"] != float64(64) {
		t.Fatalf("unexpected stream counts: %+v", payload)
	}
	if payload["dial_errors_total"] != float64(1) || payload["streams_rejected_total"] != float64(1) {
		t.Fatalf("unexpected error/reject counts: %+v", payload)
	}
	if payload["uptime_seconds"].(float64) < 29 {
		t.Fatalf("unexpected uptime_seconds: %+v", payload["uptime_seconds"])
	}
}
