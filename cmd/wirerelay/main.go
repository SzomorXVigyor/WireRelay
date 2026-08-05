package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "SzomorXVigyor/WireRelay/proto/wirerelay/v1"
)

type server struct {
	pb.UnimplementedWireRelayServiceServer
	iface string
}

func main() {
	iface := getEnv("WIRERELAY_IFACE", "wg0")
	grpcPort := getEnv("WIRERELAY_GRPC_PORT", "9000")
	httpPort := getEnv("WIRERELAY_HTTP_PORT", "8080")

	flag.StringVar(&iface, "iface", iface, "WireGuard interface name")
	flag.StringVar(&grpcPort, "grpc-port", grpcPort, "gRPC Server Port")
	flag.StringVar(&httpPort, "http-port", httpPort, "REST Health HTTP Port")
	flag.Parse()

	log.Printf("[WireRelay] Starting daemon (Interface: %s, gRPC: :%s, REST: :%s)", iface, grpcPort, httpPort)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup

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
		runGRPCServer(ctx, grpcPort, iface)
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

// --- gRPC API Handlers ---

func (s *server) GetHealth(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
	targetIface := req.GetInterface()
	if targetIface == "" {
		targetIface = s.iface
	}
	st, age := inspectWireGuardHandshake(targetIface)
	return &pb.HealthResponse{
		Interface:           targetIface,
		Status:              st,
		HandshakeAgeSeconds: age,
		Timestamp:           time.Now().Unix(),
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

	conn, err := net.DialTimeout("tcp", addr, timeout)
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
	in, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to read initial frame: %v", err)
	}

	header := in.GetHeader()
	if header == nil {
		return status.Error(codes.InvalidArgument, "first frame must be TunnelHeader")
	}

	targetAddr := net.JoinHostPort(header.GetTargetHost(), strconv.Itoa(int(header.GetTargetPort())))
	timeout := time.Duration(header.GetTimeoutMs()) * time.Millisecond
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	var targetConn net.Conn
	if header.GetProtocol() == pb.TransportProtocol_TRANSPORT_PROTOCOL_UDP {
		raddr, err := net.ResolveUDPAddr("udp", targetAddr)
		if err != nil {
			stream.Send(&pb.TunnelFrame{Frame: &pb.TunnelFrame_Ack{Ack: &pb.TunnelAck{Success: false, ErrorMessage: err.Error()}}})
			return status.Errorf(codes.NotFound, "failed to resolve UDP target: %v", err)
		}
		targetConn, err = net.DialUDP("udp", nil, raddr)
	} else {
		dialer := net.Dialer{Timeout: timeout}
		targetConn, err = dialer.Dial("tcp", targetAddr)
	}

	if err != nil {
		stream.Send(&pb.TunnelFrame{Frame: &pb.TunnelFrame_Ack{Ack: &pb.TunnelAck{Success: false, ErrorMessage: err.Error()}}})
		return status.Errorf(codes.Unavailable, "dial target failed: %v", err)
	}
	defer targetConn.Close()

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

	var wg sync.WaitGroup
	wg.Add(2)

	// Ingress: gRPC Stream -> Target Socket
	go func() {
		defer wg.Done()
		for {
			frame, err := stream.Recv()
			if err != nil {
				return
			}
			payload := frame.GetPayload()
			if len(payload) > 0 {
				targetConn.Write(payload)
			}
		}
	}()

	// Egress: Target Socket -> gRPC Stream
	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			n, err := targetConn.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				err = stream.Send(&pb.TunnelFrame{
					Frame: &pb.TunnelFrame_Payload{
						Payload: buf[:n],
					},
				})
				if err != nil {
					return
				}
			}
		}
	}()

	wg.Wait()
	return nil
}

// --- WireGuard Interface Inspection ---

func inspectWireGuardHandshake(iface string) (pb.TunnelStatus, int64) {
	out, err := exec.Command("wg", "show", iface, "latest-handshakes").Output()
	if err != nil {
		return pb.TunnelStatus_TUNNEL_STATUS_DISCONNECTED, -1
	}

	lines := strings.Split(string(out), "\n")
	var latestTs int64 = 0
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			ts, err := strconv.ParseInt(fields[1], 10, 64)
			if err == nil && ts > latestTs {
				latestTs = ts
			}
		}
	}

	if latestTs == 0 {
		return pb.TunnelStatus_TUNNEL_STATUS_DISCONNECTED, -1
	}

	age := time.Now().Unix() - latestTs
	if age <= 180 {
		return pb.TunnelStatus_TUNNEL_STATUS_CONNECTED, age
	} else if age <= 300 {
		return pb.TunnelStatus_TUNNEL_STATUS_DEGRADED, age
	}
	return pb.TunnelStatus_TUNNEL_STATUS_DISCONNECTED, age
}

// --- Server Lifecycle Setup ---

func runGRPCServer(ctx context.Context, port, iface string) {
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("[WireRelay] Failed to bind gRPC port :%s: %v", port, err)
	}

	s := grpc.NewServer()
	pb.RegisterWireRelayServiceServer(s, &server{iface: iface})

	log.Printf("[WireRelay] gRPC service ready on :%s", port)

	go func() {
		<-ctx.Done()
		s.GracefulStop()
	}()

	if err := s.Serve(lis); err != nil && err != grpc.ErrServerStopped {
		log.Printf("[WireRelay] gRPC server error: %v", err)
	}
}

func runRESTServer(ctx context.Context, port, iface string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		st, age := inspectWireGuardHandshake(iface)
		if st == pb.TunnelStatus_TUNNEL_STATUS_DISCONNECTED {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"interface":             iface,
			"status":                st.String(),
			"handshake_age_seconds": age,
			"timestamp":             time.Now().Unix(),
		})
	})

	srv := &http.Server{Addr: ":" + port, Handler: mux}

	go func() {
		log.Printf("[WireRelay] REST Health API ready on :%s/health", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[WireRelay] REST server error: %v", err)
		}
	}()

	<-ctx.Done()
	srv.Shutdown(context.Background())
}
