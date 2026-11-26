#!/bin/sh
set -e

IFACE="${WIRERELAY_IFACE:-wg0}"
SRC_CONFIG="/etc/wireguard/${IFACE}.conf"
RUN_DIR="/run/wireguard"
RUN_CONFIG="${RUN_DIR}/${IFACE}.conf"
DDNS_META="${RUN_DIR}/${IFACE}.ddns"

mkdir -p "$RUN_DIR"
chmod 700 "$RUN_DIR"

shred_file() {
    target="$1"
    if [ -f "$target" ]; then
        sz="$(wc -c < "$target" 2>/dev/null || echo 0)"
        if [ "$sz" -gt 0 ] 2>/dev/null; then
            dd if=/dev/zero of="$target" bs=1 count="$sz" conv=notrunc 2>/dev/null || true
        fi
        rm -f "$target"
    fi
}

# 1. Materialize startup config into container-private tmpfs (/run/wireguard)
#    Precedence: WIRERELAY_CONF_STDIN -> WIREGUARD_CONF_STR -> /etc/wireguard/<iface>.conf
if [ "$WIRERELAY_CONF_STDIN" = "true" ] || [ "$WIRERELAY_CONF_STDIN" = "1" ]; then
    echo "[entrypoint] Reading startup WireGuard config from stdin..."
    cat > "$RUN_CONFIG"
    chmod 600 "$RUN_CONFIG"
    if [ ! -s "$RUN_CONFIG" ]; then
        shred_file "$RUN_CONFIG"
        echo "[entrypoint] ERROR: WIRERELAY_CONF_STDIN is enabled but stdin was empty." >&2
        exit 1
    fi
elif [ -n "$WIREGUARD_CONF_STR" ]; then
    echo "[entrypoint] Found WIREGUARD_CONF_STR environment variable. Writing temporary config to $RUN_CONFIG..."
    printf "%s\n" "$WIREGUARD_CONF_STR" > "$RUN_CONFIG"
    chmod 600 "$RUN_CONFIG"
    unset WIREGUARD_CONF_STR
elif [ -f "$SRC_CONFIG" ]; then
    echo "[entrypoint] Copying mounted config $SRC_CONFIG to temporary $RUN_CONFIG..."
    cp "$SRC_CONFIG" "$RUN_CONFIG"
    chmod 600 "$RUN_CONFIG"
fi

# 2. Harden container network forwarding so site LAN traffic cannot traverse onto container net (R11)
sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null 2>&1 || true
iptables -P FORWARD DROP >/dev/null 2>&1 || true

# 3. Bring up WireGuard interface if a boot-time config was supplied
WG_UP=0
if [ -f "$RUN_CONFIG" ]; then
    # Extract ONLY non-secret [Peer] PublicKey + Endpoint lines for the DDNS watcher
    # so zero private keys or preshared keys persist in /run/wireguard after wg-quick up.
    awk '
    /^[ \t]*\[/ {
        sec = tolower($0)
        gsub(/[ \t\r\[\]]/, "", sec)
        in_peer = (sec == "peer")
        if (in_peer) print "[Peer]"
        next
    }
    in_peer {
        low = tolower($0)
        if (low ~ /^[ \t]*(publickey|endpoint)[ \t]*=/) {
            print
        }
    }
    ' "$RUN_CONFIG" > "$DDNS_META"
    chmod 600 "$DDNS_META"

    # Strip DNS directives to prevent resolvconf errors inside Docker (BusyBox-safe)
    sed -i '/^[[:space:]]*[Dd][Nn][Ss][[:space:]]*=/d' "$RUN_CONFIG"

    # Strip IPv6 addresses/routes if DISABLE_IPV6 or WIREGUARD_DISABLE_IPV6 is set to true/1
    if [ "$DISABLE_IPV6" = "true" ] || [ "$DISABLE_IPV6" = "1" ] || \
       [ "$WIREGUARD_DISABLE_IPV6" = "true" ] || [ "$WIREGUARD_DISABLE_IPV6" = "1" ]; then
        echo "[entrypoint] DISABLE_IPV6 is enabled. Stripping IPv6 addresses from $RUN_CONFIG..."
        awk '
        {
            line_lower = tolower($0)
            if (line_lower ~ /^[ \t]*(address|allowedips)[ \t]*=/) {
                split($0, parts, "=")
                key = parts[1]
                val = parts[2]
                n = split(val, ips, ",")
                new_val = ""
                for (i = 1; i <= n; i++) {
                    gsub(/^[ \t]+|[ \t]+$/, "", ips[i])
                    if (ips[i] !~ /:/ && ips[i] != "") {
                        if (new_val != "") {
                            new_val = new_val ", " ips[i]
                        } else {
                            new_val = ips[i]
                        }
                    }
                }
                if (new_val != "") {
                    print key "= " new_val
                }
                next
            }
            print
        }
        ' "$RUN_CONFIG" > "${RUN_CONFIG}.tmp" && mv "${RUN_CONFIG}.tmp" "$RUN_CONFIG"
        chmod 600 "$RUN_CONFIG"

        # Pre-resolve hostname Endpoints to IPv4 (A record only) so Alpine/musl wg does not
        # fail with EAI_AGAIN when upstream DNS returns SERVFAIL on AAAA queries.
        EP_LINE="$(grep -i '^[[:space:]]*Endpoint[[:space:]]*=' "$RUN_CONFIG" | head -n 1 || true)"
        if [ -n "$EP_LINE" ]; then
            EP_VAL="$(printf "%s" "$EP_LINE" | cut -d'=' -f2- | tr -d ' \t\r')"
            EP_HOST="${EP_VAL%:*}"
            EP_PORT="${EP_VAL##*:}"
            case "$EP_HOST" in
                *[!0-9.]*)
                    RESOLVED_IP="$(/usr/local/bin/wirerelay -resolve-v4 "$EP_HOST" 2>/dev/null || true)"
                    if [ -n "$RESOLVED_IP" ]; then
                        echo "[entrypoint] Resolved IPv4 endpoint ${EP_HOST} -> ${RESOLVED_IP}:${EP_PORT}"
                        awk -v target="${RESOLVED_IP}:${EP_PORT}" '
                        tolower($0) ~ /^[ \t]*endpoint[ \t]*=/ { print "Endpoint = " target; next }
                        { print }
                        ' "$RUN_CONFIG" > "${RUN_CONFIG}.tmp" && mv "${RUN_CONFIG}.tmp" "$RUN_CONFIG"
                        chmod 600 "$RUN_CONFIG"
                    fi
                    ;;
            esac
        fi
    fi

    echo "[entrypoint] Initializing WireGuard interface ${IFACE}..."
    if ! wg-quick up "$RUN_CONFIG"; then
        shred_file "$RUN_CONFIG"
        exit 1
    fi
    # Immediately overwrite and delete temporary plaintext config (private key stays in kernel only)
    shred_file "$RUN_CONFIG"
    WG_UP=1
elif [ "$WIRERELAY_WAIT_FOR_CONFIG" = "true" ] || [ "$WIRERELAY_WAIT_FOR_CONFIG" = "1" ]; then
    echo "[entrypoint] Waiting for startup WireGuard configuration via authenticated gRPC Configure RPC..."
else
    echo "[entrypoint] No boot-time WireGuard config supplied. Starting WireRelay (ready for authenticated gRPC Configure RPC or standalone mode)..."
fi

CHILD_PID=""
cleanup() {
    echo "[entrypoint] Caught shutdown signal, stopping WireRelay..."
    if [ -n "$CHILD_PID" ]; then
        kill -TERM "$CHILD_PID" 2>/dev/null || true
        wait "$CHILD_PID" 2>/dev/null || true
    fi
    if [ "$WG_UP" = "1" ]; then
        ip link delete dev "$IFACE" 2>/dev/null || true
    fi
    rm -f "$DDNS_META"
    exit 0
}
trap cleanup INT TERM

echo "[entrypoint] Starting WireRelay gRPC/REST service..."
/usr/local/bin/wirerelay &
CHILD_PID=$!

wait "$CHILD_PID"
EXIT_CODE=$?
if [ "$WG_UP" = "1" ]; then
    ip link delete dev "$IFACE" 2>/dev/null || true
fi
rm -f "$DDNS_META"
exit "$EXIT_CODE"
