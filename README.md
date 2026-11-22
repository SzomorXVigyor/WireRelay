# WireRelay

`WireRelay` is a high-performance, single-binary gRPC tunnel relay and health monitor designed for containerized WireGuard instances. 

It enables microservices to dynamically reach devices inside isolated edge subnets by establishing bidirectional gRPC byte streams over a local WireGuard tunnel interface.

---

## Features

- **Dynamic L3 Streaming**: Tunnel any TCP or UDP connection (SSH, HTTP, Modbus, VNC) through WireGuard using bidirectional gRPC streams (`TunnelStream`).
- **Kernel-Level Health Checks**: Queries Linux kernel WireGuard netlink metrics to report handshake staleness via gRPC and REST APIs.
- **Inline Config Injection**: Support for supplying WireGuard `.conf` files via inline environment variables (`WIREGUARD_CONF_STR`) or file volume mounts.

---

## Deployment & Configuration

### Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `WIRERELAY_IFACE` | `wg0` | Target WireGuard interface to monitor and route over. |
| `WIRERELAY_GRPC_PORT` | `9000` | Port for the gRPC Tunnel Relay & API. |
| `WIRERELAY_HTTP_PORT` | `8080` | Port for the REST Health Check JSON API. |
| `WIREGUARD_CONF_STR` | `""` | Raw WireGuard `.conf` string payload (written to `/run/wireguard/<iface>.conf` on startup if present). |
| `DISABLE_IPV6` | `false` | When `true` or `1`, strips all IPv6 addresses and routes from `Address` and `AllowedIPs`. |
| `WIRERELAY_AUTH_TOKEN` | `""` | Optional bearer token enforced on all gRPC calls (`authorization: Bearer <token>` or `x-wirerelay-token`). |
| `WIRERELAY_MAX_CONCURRENT_STREAMS` | `256` | Maximum concurrent `TunnelStream` RPCs allowed by the relay. |
| `WIRERELAY_DNS_RESOLVE_INTERVAL` | `60s` | Periodic DDNS endpoint re-resolution interval (`0` disables). |

---

### Deployment Examples

#### Option 1: Inline Environment Variable Configuration (With IPv6 Disabled)

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

#### Option 2: Volume Mounted File Configuration

```bash
docker run -d \
  --name site-gw \
  --cap-add=NET_ADMIN \
  -v /path/to/site-alpha-wg0.conf:/etc/wireguard/wg0.conf:ro \
  -p 8080:8080 \
  -p 9000:9000 \
  wirerelay:latest

```

#### Option 3: Docker Compose

```yaml
services:
  site-gw:
    image: wirerelay:latest
    container_name: site-gw
    cap_add:
      - NET_ADMIN
    environment:
      - DISABLE_IPV6=true
      - WIREGUARD_CONF_STR=${SITE_ALPHA_WG_CONF}
    ports:
      - "8080:8080"
      - "9000:9000"

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
}

message HealthRequest {
  string interface = 1; // Optional: Default is "wg0"
}

enum TunnelStatus {
  TUNNEL_STATUS_UNSPECIFIED = 0;
  TUNNEL_STATUS_CONNECTED = 1;     // Handshake <= 180s
  TUNNEL_STATUS_DEGRADED = 2;      // 180s < Handshake <= 300s
  TUNNEL_STATUS_DISCONNECTED = 3;  // Handshake > 300s or inactive
}

message HealthResponse {
  string interface = 1;
  TunnelStatus status = 2;
  int64 handshake_age_seconds = 3;
  int64 timestamp = 4;
}

message PingRequest {
  string target_host = 1; // IPv4, IPv6, or Domain Name
  uint32 target_port = 2; // Target port for TCP probe
  uint32 timeout_ms = 3;  // Timeout in milliseconds (default: 2000ms)
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
  string target_host = 1;           // IPv4, IPv6, or Domain Name
  uint32 target_port = 2;           // Destination Port
  TransportProtocol protocol = 3;  // TCP (1) or UDP (2)
  uint32 timeout_ms = 4;           // Custom dial timeout in ms (default: 5000ms)
}

message TunnelAck {
  bool success = 1;
  string error_message = 2;
  string local_bound_address = 3;
}

message TunnelFrame {
  oneof frame {
    TunnelHeader header = 1; // Sent in first request by client
    TunnelAck ack = 2;       // Sent in first response by server
    bytes payload = 3;       // Subsequent full-duplex stream payload bytes
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
  "status": "TUNNEL_STATUS_CONNECTED",
  "handshake_age_seconds": 14,
  "timestamp": 1775335500
}

```

### gRPC Endpoint

`rpc GetHealth (HealthRequest) returns (HealthResponse);`

### Status States

* `TUNNEL_STATUS_CONNECTED`: Handshake age $\le 180 \text{ seconds}$.
* `TUNNEL_STATUS_DEGRADED`: $180 \text{ seconds} < \text{Age} \le 300 \text{ seconds}$.
* `TUNNEL_STATUS_DISCONNECTED`: Age $> 300 \text{ seconds}$ or interface down (REST returns `503 Service Unavailable`).

## Release

Releases are tagged from the `main` branch and auto published on Github Registry as Docker images. To create a new release:

1. Commit the change and push to `main`.
2. Create a new tag matching the version (e.g. `git tag v1.0.0`).
3. Push the tag to trigger the release workflow (e.g. `git push origin v1.0.0`).