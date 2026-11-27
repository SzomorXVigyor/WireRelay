# WireRelay

`WireRelay` is a high-performance, single-binary gRPC tunnel relay and health monitor designed for containerized WireGuard instances.

It enables microservices to dynamically reach devices inside isolated edge subnets by establishing bidirectional gRPC byte streams over a local WireGuard tunnel interface.

---

## Features

- **Dynamic L3 Streaming**: Tunnel any TCP or UDP connection (SSH, HTTP, Modbus, VNC) through WireGuard using bidirectional gRPC streams (`TunnelStream`).
- **Kernel-Level Health Checks**: Queries Linux kernel WireGuard netlink metrics to report per-peer handshake staleness via gRPC and REST APIs.
- **Zero-File Startup Config Pass**: Supply WireGuard `.conf` payloads over an authenticated gRPC `Configure` RPC or `stdin` pipe (`WIRERELAY_CONF_STDIN=true`) with zero host bind mounts and zero environment variable secret exposure.
- **Automatic Tmpfs Shredding**: Temporary runtime `.conf` files written to `/run/wireguard/` are overwritten with zeros and deleted immediately after `wg-quick up`, leaving no plaintext private keys on disk inside or outside the container.
- **DDNS Endpoint Watcher**: Periodically re-resolves hostname-based `[Peer]` endpoints without retaining private keys on disk.

---

## Deployment & Configuration

### Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `WIRERELAY_IFACE` | `wg0` | Target WireGuard interface to configure, monitor, and route over. |
| `WIRERELAY_GRPC_PORT` | `9000` | Port for the gRPC Tunnel Relay & Control API. |
| `WIRERELAY_HTTP_PORT` | `8080` | Port for the REST Health Check JSON API. |
| `WIRERELAY_AUTH_TOKEN` | `""` | Bearer token enforced on all gRPC calls (`authorization: Bearer <token>` or `x-wirerelay-token`). **Required** to use the gRPC `Configure` RPC. |
| `WIRERELAY_WAIT_FOR_CONFIG` | `false` | When `true` or `1`, boots cleanly without a boot-time file/env config and waits for the authenticated gRPC `Configure` RPC. |
| `WIRERELAY_ALLOW_RECONFIGURE` | `false` | By default, `Configure` is startup-only (locked after first successful apply). Set `true` to allow live reconfiguration via gRPC without recreating the container. |
| `WIRERELAY_CONF_STDIN` | `false` | When `true` or `1`, reads the WireGuard `.conf` payload from `stdin` on startup, applies it, and immediately shreds the temporary file. |
| `WIREGUARD_CONF_STR` | `""` | Legacy inline WireGuard `.conf` string payload (applied on startup, then unset and shredded from `/run/wireguard`). |
| `DISABLE_IPV6` | `false` | When `true` or `1`, strips all IPv6 addresses and routes from `Address` and `AllowedIPs` and pre-resolves hostname endpoints to IPv4. |
| `WIRERELAY_MAX_CONCURRENT_STREAMS` | `256` | Maximum concurrent `TunnelStream` RPCs allowed by the relay. |
| `WIRERELAY_DNS_RESOLVE_INTERVAL` | `60s` | Periodic DDNS endpoint re-resolution interval (`0` disables). |

---

## Startup Config Pass (Zero Host Files)

WireRelay supports four configuration delivery methods, ordered from most secure to legacy:

| Method | Plaintext on Host Disk | Visible in `docker inspect` | Survives Container Restart | Best For |
| :--- | :--- | :--- | :--- | :--- |
| **gRPC `Configure` RPC** | None | No | Yes (orchestrator re-pushes when `configured=false`) | Orchestrators / Multi-tenant platforms (e.g. WireDeck2) |
| **`stdin` Pipe (`WIRERELAY_CONF_STDIN=true`)** | None | No | No (`stdin` closes after boot) | One-shot CLI / ephemeral runs |
| **Read-only File Mount (`/etc/wireguard/wg0.conf:ro`)** | Host path (use `tmpfs`) | Mount path only | Yes | Static single-host Docker Compose |
| **Env Var (`WIREGUARD_CONF_STR`)** | None | **Yes** | Yes | Local dev / quick testing only |

> **Security note on temporary files:** Regardless of which startup method is used, WireRelay writes the sanitized config only briefly inside the container's `/run/wireguard/<iface>.conf` (`0600`), runs `wg-quick up`, and immediately overwrites it with zeros and deletes it. Only non-secret DDNS metadata (`PublicKey` and `Endpoint` hostnames) is retained for periodic DNS re-resolution.

---

### Option 1 (Recommended): Authenticated gRPC Startup Config Push (`Configure` RPC)

Start the container with **no config file mount and no config env var**, protected by a per-runner `WIRERELAY_AUTH_TOKEN`:

```bash
docker run -d \
  --name site-gw \
  --cap-add=NET_ADMIN \
  -e WIRERELAY_WAIT_FOR_CONFIG=true \
  -e WIRERELAY_AUTH_TOKEN="your-32-byte-random-token" \
  -e DISABLE_IPV6=true \
  -p 8080:8080 \
  -p 9000:9000 \
  wirerelay:latest
```

Then push the WireGuard config once over authenticated gRPC from your orchestrator or CLI (`grpcurl` example):

```bash
grpcurl -plaintext \
  -H "authorization: Bearer your-32-byte-random-token" \
  -d "$(jq -n --rawfile conf ./wg0.conf '{config: $conf, disable_ipv6: true}')" \
  127.0.0.1:9000 \
  wirerelay.v1.WireRelayService/Configure
```

**Startup lock & restart behavior:**
- `Configure` **fails closed** (`FailedPrecondition`) if `WIRERELAY_AUTH_TOKEN` is not set.
- By default (`WIRERELAY_ALLOW_RECONFIGURE=false`), `Configure` is **one-shot at startup**: once applied, any subsequent `Configure` call returns `AlreadyExists`. To rotate keys, either recreate the container or explicitly opt in with `WIRERELAY_ALLOW_RECONFIGURE=true`.
- If the container restarts (crash or host reboot), `GetHealth` and `GET /health` report `"configured": false` (and `HANDSHAKE_STATE_INTERFACE_ERROR`), signaling the orchestrator's reconciliation loop to re-push the WireGuard config automatically.

---

### Option 2: Zero-File `stdin` Startup Pipe (`WIRERELAY_CONF_STDIN=true`)

Pass the config directly over standard input with `docker run -i` (no host bind mount and no env var secret):

```bash
docker run -i \
  --name site-gw \
  --cap-add=NET_ADMIN \
  -e WIRERELAY_CONF_STDIN=true \
  -e DISABLE_IPV6=true \
  -e WIRERELAY_AUTH_TOKEN="your-32-byte-random-token" \
  -p 8080:8080 \
  -p 9000:9000 \
  wirerelay:latest < /path/to/site-alpha-wg0.conf
```

The entrypoint reads `stdin` until EOF, initializes WireGuard, shreds `/run/wireguard/wg0.conf`, and starts the WireRelay daemon.

---

### Option 3: Read-Only Volume Mounted File Configuration

```bash
docker run -d \
  --name site-gw \
  --cap-add=NET_ADMIN \
  -v /path/to/site-alpha-wg0.conf:/etc/wireguard/wg0.conf:ro \
  -p 8080:8080 \
  -p 9000:9000 \
  wirerelay:latest
```

---

### Option 4: Inline Environment Variable Configuration (Dev / Testing)

```bash
docker run -d \
  --name site-gw \
  --cap-add=NET_ADMIN \
  -e DISABLE_IPV6=true \
  -e WIREGUARD_CONF_STR="[Interface]
PrivateKey = aaaaaa...
Address = 10.200.0.2/32, fd80::2/128

[Peer]
PublicKey = bbbbbb...
Endpoint = vpn.example.com:51820
AllowedIPs = 192.168.1.0/24, ::/0" \
  -p 8080:8080 \
  -p 9000:9000 \
  wirerelay:latest
```

---

## gRPC Service Definition (`wirerelay.proto`)

```protobuf
syntax = "proto3";

package wirerelay.v1;

option go_package = "wirerelay/v1;wirerelayv1";

service WireRelayService {
  // GetHealth returns current WireGuard interface health and handshake metrics.
  rpc GetHealth (HealthRequest) returns (HealthResponse);

  // PingTarget executes a TCP reachability probe to a target host inside the site network.
  rpc PingTarget (PingRequest) returns (PingResponse);

  // TunnelStream establishes a full-duplex, bidirectional byte stream to a target host over WireGuard.
  rpc TunnelStream (stream TunnelFrame) returns (stream TunnelFrame);

  // Configure pushes a WireGuard configuration over authenticated gRPC at startup.
  rpc Configure (ConfigureRequest) returns (ConfigureResponse);

  // GetStats returns WireGuard traffic counters and relay stream runtime statistics.
  rpc GetStats (StatsRequest) returns (StatsResponse);
}

message StatsRequest {
  string interface = 1; // Optional: defaults to WIRERELAY_IFACE ("wg0")
}

message PeerTransferStats {
  string public_key = 1;
  uint64 rx_bytes = 2;
  uint64 tx_bytes = 3;
}

message StatsResponse {
  string interface = 1;
  uint64 rx_bytes = 2;
  uint64 tx_bytes = 3;
  int64 uptime_seconds = 4;
  uint32 active_streams = 5;
  uint32 max_streams = 6;
  uint64 dial_errors_total = 7;
  uint64 streams_rejected_total = 8;
  repeated PeerTransferStats peers = 9;
  int64 timestamp = 10;
  string error_message = 11;
}

message ConfigureRequest {
  string interface = 1;  // Optional: defaults to WIRERELAY_IFACE ("wg0")
  string config = 2;     // Required: raw WireGuard .conf payload
  bool disable_ipv6 = 3; // Optional: strip IPv6 addresses/routes and force IPv4 endpoint resolution
}

message ConfigureResponse {
  bool applied = 1;
  string interface = 2;
  string error_message = 3;
}

message HealthRequest {
  string interface = 1; // Optional: Default is WIRERELAY_IFACE ("wg0")
}

enum TunnelStatus {
  TUNNEL_STATUS_UNSPECIFIED = 0;
  TUNNEL_STATUS_CONNECTED = 1;     // All peers handshaked <= 180s
  TUNNEL_STATUS_DEGRADED = 2;      // Worst peer 180s < Handshake <= 300s
  TUNNEL_STATUS_DISCONNECTED = 3;  // Any peer > 300s, never handshaked, or interface error
}

enum HandshakeState {
  HANDSHAKE_STATE_UNSPECIFIED = 0;
  HANDSHAKE_STATE_CONNECTED = 1;
  HANDSHAKE_STATE_DEGRADED = 2;
  HANDSHAKE_STATE_STALE = 3;
  HANDSHAKE_STATE_NEVER_HANDSHAKED = 4;
  HANDSHAKE_STATE_INTERFACE_ERROR = 5;
}

message PeerHealth {
  string public_key = 1;
  int64 handshake_age_seconds = 2;
  HandshakeState state = 3;
}

message HealthResponse {
  string interface = 1;
  TunnelStatus status = 2;
  int64 handshake_age_seconds = 3;
  int64 timestamp = 4;
  HandshakeState handshake_state = 5;
  string error_message = 6;
  repeated PeerHealth peers = 7;
  bool configured = 8;
}

message PingRequest {
  string target_host = 1;
  uint32 target_port = 2;
  uint32 timeout_ms = 3;
}

message PingResponse {
  bool reachable = 1;
  uint32 latency_ms = 2;
  string error_message = 3;
}

enum TransportProtocol {
  TRANSPORT_PROTOCOL_UNSPECIFIED = 0;
  TRANSPORT_PROTOCOL_TCP = 1;
  TRANSPORT_PROTOCOL_UDP = 2;
}

message TunnelHeader {
  string target_host = 1;
  uint32 target_port = 2;
  TransportProtocol protocol = 3;
  uint32 timeout_ms = 4;
}

message TunnelAck {
  bool success = 1;
  string error_message = 2;
  string local_bound_address = 3;
}

message TunnelClose {
  string reason = 1;
}

message TunnelFrame {
  oneof frame {
    TunnelHeader header = 1;
    TunnelAck ack = 2;
    bytes payload = 3;
    TunnelClose close = 4;
  }
}
```

---

## Health Monitoring API

### REST JSON Endpoint

`GET http://<container>:8080/health`

**Response (`200 OK`):**

```json
{
  "interface": "wg0",
  "configured": true,
  "status": "TUNNEL_STATUS_CONNECTED",
  "handshake_state": "HANDSHAKE_STATE_CONNECTED",
  "handshake_age_seconds": 14,
  "timestamp": 1775335500
}
```

### gRPC Endpoints

- `rpc GetHealth (HealthRequest) returns (HealthResponse);`
- `rpc GetStats (StatsRequest) returns (StatsResponse);`

### REST Stats Endpoint

`GET http://<container>:8080/stats`

**Response (`200 OK`):**

```json
{
  "interface": "wg0",
  "rx_bytes": 1048576,
  "tx_bytes": 524288,
  "uptime_seconds": 3600,
  "active_streams": 4,
  "max_streams": 256,
  "dial_errors_total": 0,
  "streams_rejected_total": 0,
  "peers": [
    {
      "public_key": "peer-public-key=",
      "rx_bytes": 1048576,
      "tx_bytes": 524288
    }
  ],
  "timestamp": 1775335500
}
```

### Status States

- `TUNNEL_STATUS_CONNECTED`: Handshake age <= 180 seconds.
- `TUNNEL_STATUS_DEGRADED`: 180 seconds < Age <= 300 seconds.
- `TUNNEL_STATUS_DISCONNECTED`: Age > 300 seconds, unconfigured (`configured: false`), or interface down (REST returns `503 Service Unavailable`).

---

## Release

Releases are tagged from the `main` branch and auto published on GitHub Container Registry as Docker images. To create a new release:

1. Commit the change and push to `main`.
2. Create a new tag matching the version (e.g. `git tag v1.2.0`).
3. Push the tag to trigger the release workflow (e.g. `git push origin v1.2.0`).
