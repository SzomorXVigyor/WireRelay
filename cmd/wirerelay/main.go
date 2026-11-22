package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	pb "SzomorXVigyor/WireRelay/proto/wirerelay/v1"
)

const (
	defaultMaxConcurrentStreams = 256
	defaultDNSResolveInterval   = 60 * time.Second
)

type server struct {
	pb.UnimplementedWireRelayServiceServer
	iface       string
	shutdownCtx context.Context
	streamSem   chan struct{}
}

func newRelayServer(shutdownCtx context.Context, iface string, maxStreams int) *server {
	if maxStreams < 1 {
		maxStreams = defaultMaxConcurrentStreams
	}
	return &server{
		iface:       iface,
		shutdownCtx: shutdownCtx,
		streamSem:   make(chan struct{}, maxStreams),
	}
}

func main() {
	iface := getEnv("WIRERELAY_IFACE", "wg0")
	grpcPort := getEnv("WIRERELAY_GRPC_PORT", "9000")
	httpPort := getEnv("WIRERELAY_HTTP_PORT", "8080")
	authToken := os.Getenv("WIRERELAY_AUTH_TOKEN")
	disableIPv6 := isTruthy(os.Getenv("DISABLE_IPV6")) || isTruthy(os.Getenv("WIREGUARD_DISABLE_IPV6"))

	maxStreams := defaultMaxConcurrentStreams
	if raw := os.Getenv("WIRERELAY_MAX_CONCURRENT_STREAMS"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			maxStreams = parsed
		}
	}

	dnsInterval := defaultDNSResolveInterval
	if raw := os.Getenv("WIRERELAY_DNS_RESOLVE_INTERVAL"); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed >= 0 {
			dnsInterval = parsed
		}
	}

	flag.StringVar(&iface, "iface", iface, "WireGuard interface name")
	flag.StringVar(&grpcPort, "grpc-port", grpcPort, "gRPC Server Port")
	flag.StringVar(&httpPort, "http-port", httpPort, "REST Health HTTP Port")
	flag.Parse()

	log.Printf("[WireRelay] Starting daemon (Interface: %s, gRPC: :%s, REST: :%s, MaxStreams: %d, Auth: %v)",
		iface, grpcPort, httpPort, maxStreams, authToken != "")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup

	// DDNS periodic endpoint re-resolver (R6)
	wg.Add(1)
	go func() {
		defer wg.Done()
		runDDNSResolver(ctx, iface, dnsInterval, disableIPv6)
	}()

	// REST HTTP Health API
	wg.Add(1)
	go func() {
		defer wg.Done()
		runRESTServer(ctx, httpPort, iface)
	}()

	// gRPC Relay Server
	wg.Add(1)
	go func() {
		defer wg.Done()
		runGRPCServer(ctx, grpcPort, iface, authToken, maxStreams)
	}()

	<-ctx.Done()
	log.Println("[WireRelay] Shutdown signal received. Cleaning up...")
	wg.Wait()
	log.Println("[WireRelay] Stopped cleanly.")
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return fallback
}

func isTruthy(v string) bool {
	s := strings.ToLower(strings.TrimSpace(v))
	return s == "true" || s == "1" || s == "yes"
}

// --- gRPC API Handlers ---

func (s *server) GetHealth(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
	targetIface := req.GetInterface()
	if targetIface == "" {
		targetIface = s.iface
	}
	rep := inspectWireGuardHandshake(targetIface)
	return &pb.HealthResponse{
		Interface:           targetIface,
		Status:              rep.status,
		HandshakeAgeSeconds: rep.ageSeconds,
		Timestamp:           time.Now().Unix(),
		HandshakeState:      rep.state,
		ErrorMessage:        rep.errorMessage,
		Peers:               rep.peers,
	}, nil
}

func (s *server) PingTarget(ctx context.Context, req *pb.PingRequest) (*pb.PingResponse, error) {
	if req.GetTargetHost() == "" {
		return nil, status.Error(codes.InvalidArgument, "target_host is required")
	}

	timeout := time.Duration(req.GetTimeoutMs()) * time.Millisecond
	if timeout == 0 {
		timeout = 2 * time.Second
	}

	start := time.Now()
	addr := net.JoinHostPort(req.GetTargetHost(), strconv.Itoa(int(req.GetTargetPort())))

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return &pb.PingResponse{
			Reachable:    false,
			LatencyMs:    0,
			ErrorMessage: err.Error(),
		}, nil
	}
	conn.Close()

	return &pb.PingResponse{
		Reachable: true,
		LatencyMs: uint32(time.Since(start).Milliseconds()),
	}, nil
}

func (s *server) TunnelStream(stream pb.WireRelayService_TunnelStreamServer) error {
	// Enforce concurrent tunnel limit (R4)
	select {
	case s.streamSem <- struct{}{}:
		defer func() { <-s.streamSem }()
	default:
		return status.Error(codes.ResourceExhausted, "maximum concurrent tunnel streams reached")
	}

	in, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to read initial frame: %v", err)
	}

	header := in.GetHeader()
	if header == nil {
		return status.Error(codes.InvalidArgument, "first frame must be TunnelHeader")
	}
	if header.GetTargetHost() == "" || header.GetTargetPort() == 0 {
		return status.Error(codes.InvalidArgument, "target_host and target_port are required")
	}

	targetAddr := net.JoinHostPort(header.GetTargetHost(), strconv.Itoa(int(header.GetTargetPort())))
	timeout := time.Duration(header.GetTimeoutMs()) * time.Millisecond
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	// Tie stream lifetime to both the RPC context and daemon shutdown context (R2, R11)
	streamCtx, streamCancel := context.WithCancel(stream.Context())
	defer streamCancel()

	if s.shutdownCtx != nil {
		stopShutdownWatch := context.AfterFunc(s.shutdownCtx, streamCancel)
		defer stopShutdownWatch()
	}

	dialCtx, dialCancel := context.WithTimeout(streamCtx, timeout)
	var targetConn net.Conn
	if header.GetProtocol() == pb.TransportProtocol_TRANSPORT_PROTOCOL_UDP {
		var dialer net.Dialer
		targetConn, err = dialer.DialContext(dialCtx, "udp", targetAddr)
	} else {
		var dialer net.Dialer
		targetConn, err = dialer.DialContext(dialCtx, "tcp", targetAddr)
	}
	dialCancel()

	if err != nil {
		_ = stream.Send(&pb.TunnelFrame{
			Frame: &pb.TunnelFrame_Ack{
				Ack: &pb.TunnelAck{Success: false, ErrorMessage: err.Error()},
			},
		})
		return status.Errorf(codes.Unavailable, "dial target failed: %v", err)
	}

	// Ensure targetConn is closed immediately whenever streamCtx ends so blocked Reads
	// unblock immediately without leaking goroutines or file descriptors (R2).
	var closeOnce sync.Once
	closeTarget := func() {
		closeOnce.Do(func() {
			_ = targetConn.Close()
		})
	}
	defer closeTarget()

	stopCloseWatch := context.AfterFunc(streamCtx, closeTarget)
	defer stopCloseWatch()

	// Send Success ACK
	err = stream.Send(&pb.TunnelFrame{
		Frame: &pb.TunnelFrame_Ack{
			Ack: &pb.TunnelAck{
				Success:           true,
				LocalBoundAddress: targetConn.LocalAddr().String(),
			},
		},
	})
	if err != nil {
		return err
	}

	egressDone := make(chan struct{})
	ingressDone := make(chan struct{})

	// Ingress: gRPC Stream -> Target Socket
	go func() {
		defer close(ingressDone)
		defer closeTarget()
		for {
			frame, err := stream.Recv()
			if err != nil {
				return
			}
			if frame.GetClose() != nil {
				return
			}
			payload := frame.GetPayload()
			if len(payload) > 0 {
				if _, err := targetConn.Write(payload); err != nil {
					return
				}
			}
		}
	}()

	// Egress: Target Socket -> gRPC Stream (only goroutine calling stream.Send after ACK)
	go func() {
		defer close(egressDone)
		defer streamCancel()
		buf := make([]byte, 16384)
		for {
			n, err := targetConn.Read(buf)
			if n > 0 {
				// Copy slice before passing to stream.Send so buffer reuse is safe.
				out := make([]byte, n)
				copy(out, buf[:n])
				if sendErr := stream.Send(&pb.TunnelFrame{
					Frame: &pb.TunnelFrame_Payload{
						Payload: out,
					},
				}); sendErr != nil {
					return
				}
			}
			if err != nil {
				reason := "target_closed"
				if err != io.EOF {
					reason = err.Error()
				}
				// Notify client explicitly so it does not hang waiting on Recv (R1).
				_ = stream.Send(&pb.TunnelFrame{
					Frame: &pb.TunnelFrame_Close{
						Close: &pb.TunnelClose{Reason: reason},
					},
				})
				return
			}
		}
	}()

	// Return as soon as egress finishes (which sends TunnelClose and cancels streamCtx)
	// OR ingress finishes (which closes targetConn so egress finishes promptly).
	<-egressDone
	closeTarget()
	// Returning from TunnelStream closes the gRPC server stream, which immediately unblocks
	// any Recv() still waiting in the ingress goroutine; wait briefly so we don't leak it.
	select {
	case <-ingressDone:
	case <-time.After(100 * time.Millisecond):
	}
	return nil
}

// --- Server Lifecycle Setup ---

func runGRPCServer(ctx context.Context, port, iface, authToken string, maxStreams int) {
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("[WireRelay] Failed to bind gRPC port :%s: %v", port, err)
	}

	opts := []grpc.ServerOption{
		grpc.MaxConcurrentStreams(uint32(maxStreams)),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}
	if authToken != "" {
		opts = append(opts,
			grpc.UnaryInterceptor(unaryAuthInterceptor(authToken)),
			grpc.StreamInterceptor(streamAuthInterceptor(authToken)),
		)
	}

	s := grpc.NewServer(opts...)
	pb.RegisterWireRelayServiceServer(s, newRelayServer(ctx, iface, maxStreams))

	log.Printf("[WireRelay] gRPC service ready on :%s", port)

	go func() {
		<-ctx.Done()
		stopped := make(chan struct{})
		go func() {
			s.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			log.Println("[WireRelay] gRPC GracefulStop timed out; forcing Stop")
			s.Stop()
		}
	}()

	if err := s.Serve(lis); err != nil && err != grpc.ErrServerStopped {
		log.Printf("[WireRelay] gRPC server error: %v", err)
	}
}

func runRESTServer(ctx context.Context, port, iface string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		rep := inspectWireGuardHandshake(iface)
		// Set Content-Type BEFORE WriteHeader (R10)
		w.Header().Set("Content-Type", "application/json")
		if rep.status == pb.TunnelStatus_TUNNEL_STATUS_DISCONNECTED {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		body := map[string]any{
			"interface":             iface,
			"status":                rep.status.String(),
			"handshake_state":       rep.state.String(),
			"handshake_age_seconds": rep.ageSeconds,
			"timestamp":             time.Now().Unix(),
		}
		if rep.errorMessage != "" {
			body["error_message"] = rep.errorMessage
		}
		if len(rep.peers) > 0 {
			peers := make([]map[string]any, 0, len(rep.peers))
			for _, p := range rep.peers {
				peers = append(peers, map[string]any{
					"public_key":            p.PublicKey,
					"handshake_age_seconds": p.HandshakeAgeSeconds,
					"state":                 p.State.String(),
				})
			}
			body["peers"] = peers
		}
		_ = json.NewEncoder(w).Encode(body)
	})

	srv := &http.Server{Addr: ":" + port, Handler: mux}

	go func() {
		log.Printf("[WireRelay] REST Health API ready on :%s/health", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[WireRelay] REST server error: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
