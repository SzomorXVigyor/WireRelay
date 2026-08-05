package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "SzomorXVigyor/WireRelay/proto/wirerelay/v1"
)

//go:embed static/*
var staticFS embed.FS

type Bridge struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	RelayAddr   string `json:"relay_addr"`   // e.g. "wirerelay:9000"
	SourcePort  int    `json:"source_port"`  // e.g. 8080
	SourceProto string `json:"source_proto"` // "TCP" or "UDP"
	TargetHost  string `json:"target_host"`  // e.g. "192.168.1.50"
	TargetPort  int    `json:"target_port"`  // e.g. 80
	TargetProto string `json:"target_proto"` // "TCP" or "UDP"
	Status      string `json:"status"`       // "RUNNING"

	tcpListener net.Listener
	udpConn     *net.UDPConn
	stopChan    chan struct{}
}

type BridgeManager struct {
	mu          sync.Mutex
	defaultAddr string
	bridges     map[string]*Bridge
}

var manager = &BridgeManager{
	bridges: make(map[string]*Bridge),
}

func main() {
	httpPort := getEnv("BRIDGE_HTTP_PORT", "8090")
	manager.defaultAddr = getEnv("WIRERELAY_ADDR", getEnv("RELAY_ADDR", "localhost:9000"))

	http.HandleFunc("/api/config", handleConfig)
	http.HandleFunc("/api/bridges", handleBridges)
	http.HandleFunc("/api/bridges/", handleBridgeDelete)

	subFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("Failed to initialize static web filesystem: %v", err)
	}
	http.Handle("/", http.FileServer(http.FS(subFS)))

	server := &http.Server{Addr: ":" + httpPort}

	log.Printf("[WireRelay Bridge] Web UI active at http://localhost:%s (Relay: %s)", httpPort, manager.defaultAddr)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("[WireRelay Bridge] Shutting down active bridges...")
	manager.stopAll()
	server.Shutdown(context.Background())
	log.Println("[WireRelay Bridge] Stopped cleanly.")
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return fallback
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"default_relay_addr": manager.defaultAddr,
	})
}

func handleBridges(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		manager.mu.Lock()
		list := make([]*Bridge, 0, len(manager.bridges))
		for _, b := range manager.bridges {
			list = append(list, b)
		}
		manager.mu.Unlock()
		json.NewEncoder(w).Encode(list)

	case http.MethodPost:
		var b Bridge
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if b.RelayAddr == "" {
			b.RelayAddr = manager.defaultAddr
		}
		b.ID = fmt.Sprintf("br_%d", time.Now().UnixNano())
		b.SourceProto = strings.ToUpper(b.SourceProto)
		b.TargetProto = strings.ToUpper(b.TargetProto)

		if err := manager.startBridge(&b); err != nil {
			http.Error(w, fmt.Sprintf("Failed to bind local port: %v", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(b)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleBridgeDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/bridges/")
	if err := manager.stopBridge(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Bridge Engine ---

func (m *BridgeManager) startBridge(b *Bridge) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	b.stopChan = make(chan struct{})
	b.Status = "RUNNING"

	if b.SourceProto == "UDP" {
		addr := &net.UDPAddr{Port: b.SourcePort}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			return err
		}
		b.udpConn = conn
		go b.runUDPServer()
	} else { // TCP Default
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", b.SourcePort))
		if err != nil {
			return err
		}
		b.tcpListener = ln
		go b.runTCPServer()
	}

	m.bridges[b.ID] = b
	log.Printf("[Bridge] Started Local :%d (%s) -> WireRelay (%s) -> %s:%d (%s)",
		b.SourcePort, b.SourceProto, b.RelayAddr, b.TargetHost, b.TargetPort, b.TargetProto)

	return nil
}

func (m *BridgeManager) stopBridge(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	b, exists := m.bridges[id]
	if !exists {
		return fmt.Errorf("bridge %s not found", id)
	}

	close(b.stopChan)
	if b.tcpListener != nil {
		b.tcpListener.Close()
	}
	if b.udpConn != nil {
		b.udpConn.Close()
	}
	delete(m.bridges, id)

	log.Printf("[Bridge] Stopped local port :%d", b.SourcePort)
	return nil
}

func (m *BridgeManager) stopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, b := range m.bridges {
		close(b.stopChan)
		if b.tcpListener != nil {
			b.tcpListener.Close()
		}
		if b.udpConn != nil {
			b.udpConn.Close()
		}
	}
}

// --- TCP Server Engine ---

func (b *Bridge) runTCPServer() {
	for {
		conn, err := b.tcpListener.Accept()
		if err != nil {
			select {
			case <-b.stopChan:
				return
			default:
				continue
			}
		}
		go b.tunnelTCPClient(conn)
	}
}

func (b *Bridge) tunnelTCPClient(clientConn net.Conn) {
	defer clientConn.Close()

	grpcConn, err := grpc.Dial(b.RelayAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("[Bridge TCP Error] Failed to connect to WireRelay (%s): %v", b.RelayAddr, err)
		return
	}
	defer grpcConn.Close()

	client := pb.NewWireRelayServiceClient(grpcConn)
	stream, err := client.TunnelStream(context.Background())
	if err != nil {
		log.Printf("[Bridge TCP Error] TunnelStream failed: %v", err)
		return
	}

	protoEnum := pb.TransportProtocol_TRANSPORT_PROTOCOL_TCP
	if b.TargetProto == "UDP" {
		protoEnum = pb.TransportProtocol_TRANSPORT_PROTOCOL_UDP
	}

	err = stream.Send(&pb.TunnelFrame{
		Frame: &pb.TunnelFrame_Header{
			Header: &pb.TunnelHeader{
				TargetHost: b.TargetHost,
				TargetPort: uint32(b.TargetPort),
				Protocol:   protoEnum,
				TimeoutMs:  5000,
			},
		},
	})
	if err != nil {
		return
	}

	resp, err := stream.Recv()
	if err != nil || resp.GetAck() == nil || !resp.GetAck().GetSuccess() {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			n, err := clientConn.Read(buf)
			if err != nil || n == 0 {
				return
			}
			if err := stream.Send(&pb.TunnelFrame{Frame: &pb.TunnelFrame_Payload{Payload: buf[:n]}}); err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		for {
			frame, err := stream.Recv()
			if err != nil {
				return
			}
			payload := frame.GetPayload()
			if len(payload) > 0 {
				if _, err := clientConn.Write(payload); err != nil {
					return
				}
			}
		}
	}()

	wg.Wait()
}

// --- UDP Local Server & Session Engine ---

type udpSession struct {
	stream     pb.WireRelayService_TunnelStreamClient
	grpcConn   *grpc.ClientConn
	lastActive time.Time
}

func (b *Bridge) runUDPServer() {
	sessions := make(map[string]*udpSession)
	var mu sync.Mutex

	// Sweeper for inactive UDP sessions (30s timeout)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-b.stopChan:
				return
			case <-ticker.C:
				mu.Lock()
				now := time.Now()
				for key, sess := range sessions {
					if now.Sub(sess.lastActive) > 30*time.Second {
						sess.grpcConn.Close()
						delete(sessions, key)
					}
				}
				mu.Unlock()
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := b.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-b.stopChan:
				return
			default:
				continue
			}
		}
		if n == 0 {
			continue
		}

		clientKey := clientAddr.String()
		mu.Lock()
		sess, exists := sessions[clientKey]
		if !exists {
			var err error
			sess, err = b.createUDPSession(clientAddr)
			if err != nil {
				mu.Unlock()
				log.Printf("[Bridge UDP Error] Session creation failed for %s: %v", clientKey, err)
				continue
			}
			sessions[clientKey] = sess
		}
		sess.lastActive = time.Now()
		mu.Unlock()

		// Send packet payload
		sess.stream.Send(&pb.TunnelFrame{
			Frame: &pb.TunnelFrame_Payload{
				Payload: buf[:n],
			},
		})
	}
}

func (b *Bridge) createUDPSession(clientAddr *net.UDPAddr) (*udpSession, error) {
	grpcConn, err := grpc.Dial(b.RelayAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	client := pb.NewWireRelayServiceClient(grpcConn)
	stream, err := client.TunnelStream(context.Background())
	if err != nil {
		grpcConn.Close()
		return nil, err
	}

	protoEnum := pb.TransportProtocol_TRANSPORT_PROTOCOL_TCP
	if b.TargetProto == "UDP" {
		protoEnum = pb.TransportProtocol_TRANSPORT_PROTOCOL_UDP
	}

	err = stream.Send(&pb.TunnelFrame{
		Frame: &pb.TunnelFrame_Header{
			Header: &pb.TunnelHeader{
				TargetHost: b.TargetHost,
				TargetPort: uint32(b.TargetPort),
				Protocol:   protoEnum,
				TimeoutMs:  5000,
			},
		},
	})
	if err != nil {
		grpcConn.Close()
		return nil, err
	}

	resp, err := stream.Recv()
	if err != nil || resp.GetAck() == nil || !resp.GetAck().GetSuccess() {
		grpcConn.Close()
		return nil, fmt.Errorf("WireRelay connection rejected")
	}

	sess := &udpSession{
		stream:     stream,
		grpcConn:   grpcConn,
		lastActive: time.Now(),
	}

	// Read UDP replies from WireRelay and send back to client local UDP socket
	go func() {
		for {
			frame, err := stream.Recv()
			if err != nil {
				return
			}
			payload := frame.GetPayload()
			if len(payload) > 0 {
				b.udpConn.WriteToUDP(payload, clientAddr)
			}
		}
	}()

	return sess, nil
}