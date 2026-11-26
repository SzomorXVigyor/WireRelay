package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "SzomorXVigyor/WireRelay/proto/wirerelay/v1"
)

func TestValidateInterfaceName(t *testing.T) {
	valid := []string{"wg0", "wg-site1", "wg_0.1", "a"}
	for _, v := range valid {
		if err := validateInterfaceName(v); err != nil {
			t.Fatalf("expected %q to be valid, got %v", v, err)
		}
	}
	invalid := []string{"", ".", "..", "../etc", "wg0/foo", "wg 0", "thisinterfacenameistoolong", "wg0;rm"}
	for _, v := range invalid {
		if err := validateInterfaceName(v); err == nil {
			t.Fatalf("expected %q to be invalid", v)
		}
	}
}

func TestSanitizeWireGuardConfig(t *testing.T) {
	raw := `[Interface]
PrivateKey = PRIVKEY123=
Address = 10.200.0.2/32, fd80::2/128
DNS = 1.1.1.1, 2606:4700:4700::1111

[Peer]
PublicKey = PUBKEY123=
Endpoint = vpn.example.com:51820
AllowedIPs = 192.168.10.0/24, ::/0
PersistentKeepalive = 25
`
	stubResolver := func(_ context.Context, host string) (string, error) {
		if host == "vpn.example.com" {
			return "203.0.113.42", nil
		}
		return "", nil
	}

	sanitized, peers, err := sanitizeWireGuardConfig(context.Background(), raw, true, stubResolver)
	if err != nil {
		t.Fatalf("sanitizeWireGuardConfig failed: %v", err)
	}

	if strings.Contains(sanitized, "DNS") {
		t.Fatalf("expected DNS line to be stripped:\n%s", sanitized)
	}
	if strings.Contains(sanitized, "fd80::2/128") || strings.Contains(sanitized, "::/0") {
		t.Fatalf("expected IPv6 addresses/routes to be stripped:\n%s", sanitized)
	}
	if !strings.Contains(sanitized, "Address = 10.200.0.2/32") {
		t.Fatalf("expected IPv4 Address preserved:\n%s", sanitized)
	}
	if !strings.Contains(sanitized, "AllowedIPs = 192.168.10.0/24") {
		t.Fatalf("expected IPv4 AllowedIPs preserved:\n%s", sanitized)
	}
	if !strings.Contains(sanitized, "Endpoint = 203.0.113.42:51820") {
		t.Fatalf("expected hostname endpoint pre-resolved to IPv4:\n%s", sanitized)
	}
	if len(peers) != 1 || peers[0].host != "vpn.example.com" || peers[0].port != "51820" || peers[0].publicKey != "PUBKEY123=" {
		t.Fatalf("expected DDNS peer extracted before resolution, got %+v", peers)
	}
}

func TestShredFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(p, []byte("PrivateKey = topsecret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	shredFile(p)
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("expected shredded file to be deleted, stat err=%v", err)
	}
}

func TestConfigureGRPCStartupAndLocking(t *testing.T) {
	const sampleConf = `[Interface]
PrivateKey = PRIVKEY=
Address = 10.200.0.2/32

[Peer]
PublicKey = PUBKEY=
Endpoint = ddns.site.example:51820
AllowedIPs = 192.168.1.0/24
`

	startServer := func(t *testing.T, authToken string, allowReconfig bool) (pb.WireRelayServiceClient, *ddnsWatcher, *int, func()) {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}

		ddns := &ddnsWatcher{iface: "wg0"}
		applyCount := 0
		mgr := &configManager{
			defaultIface:     "wg0",
			allowReconfigure: allowReconfig,
			defaultNoIPv6:    true,
			requireAuth:      true,
			hasAuthToken:     authToken != "",
			ddns:             ddns,
			resolveV4: func(_ context.Context, _ string) (string, error) {
				return "198.51.100.10", nil
			},
			applyFn: func(_ context.Context, _ string, _ string, _ bool) error {
				applyCount++
				return nil
			},
			teardownFn: func(string) {},
		}

		var opts []grpc.ServerOption
		if authToken != "" {
			opts = append(opts,
				grpc.UnaryInterceptor(unaryAuthInterceptor(authToken)),
				grpc.StreamInterceptor(streamAuthInterceptor(authToken)),
			)
		}
		gs := grpc.NewServer(opts...)
		pb.RegisterWireRelayServiceServer(gs, newRelayServer(context.Background(), "wg0", 4, mgr))
		go func() { _ = gs.Serve(ln) }()

		conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			gs.Stop()
			ln.Close()
			t.Fatalf("dial: %v", err)
		}
		cleanup := func() {
			conn.Close()
			gs.Stop()
			ln.Close()
		}
		return pb.NewWireRelayServiceClient(conn), ddns, &applyCount, cleanup
	}

	t.Run("fails closed when WIRERELAY_AUTH_TOKEN is unset", func(t *testing.T) {
		client, _, _, cleanup := startServer(t, "", false)
		defer cleanup()

		_, err := client.Configure(context.Background(), &pb.ConfigureRequest{Config: sampleConf})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("expected FailedPrecondition when unauthenticated, got %v", err)
		}
	})

	t.Run("startup configure applies once, updates DDNS watcher, and locks by default", func(t *testing.T) {
		const token = "test-startup-token"
		client, ddns, applyCount, cleanup := startServer(t, token, false)
		defer cleanup()

		// Without token -> Unauthenticated
		_, err := client.Configure(context.Background(), &pb.ConfigureRequest{Config: sampleConf})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}

		authCtx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))

		// Invalid config -> InvalidArgument
		_, err = client.Configure(authCtx, &pb.ConfigureRequest{Config: "not a wg config"})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("expected InvalidArgument for bad config, got %v", err)
		}

		// Valid startup push -> Applied!
		resp, err := client.Configure(authCtx, &pb.ConfigureRequest{Config: sampleConf, DisableIpv6: true})
		if err != nil {
			t.Fatalf("Configure failed: %v", err)
		}
		if !resp.GetApplied() || resp.GetInterface() != "wg0" {
			t.Fatalf("unexpected ConfigureResponse: %+v", resp)
		}
		if *applyCount != 1 {
			t.Fatalf("expected applyCount=1, got %d", *applyCount)
		}

		_, peers, _ := ddns.snapshot()
		if len(peers) != 1 || peers[0].host != "ddns.site.example" {
			t.Fatalf("expected DDNS watcher updated with peer, got %+v", peers)
		}

		// Second call must be rejected with AlreadyExists when allowReconfigure=false
		_, err = client.Configure(authCtx, &pb.ConfigureRequest{Config: sampleConf})
		if status.Code(err) != codes.AlreadyExists {
			t.Fatalf("expected AlreadyExists on second Configure call, got %v", err)
		}
	})

	t.Run("allows reconfigure when WIRERELAY_ALLOW_RECONFIGURE=true", func(t *testing.T) {
		const token = "test-reconfig-token"
		client, _, applyCount, cleanup := startServer(t, token, true)
		defer cleanup()

		authCtx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))

		if _, err := client.Configure(authCtx, &pb.ConfigureRequest{Config: sampleConf}); err != nil {
			t.Fatalf("first Configure failed: %v", err)
		}
		if _, err := client.Configure(authCtx, &pb.ConfigureRequest{Config: sampleConf}); err != nil {
			t.Fatalf("second Configure failed with allowReconfigure=true: %v", err)
		}
		if *applyCount != 2 {
			t.Fatalf("expected applyCount=2, got %d", *applyCount)
		}
	})
}
