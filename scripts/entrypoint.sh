#!/bin/sh
set -e

IFACE="${WIRERELAY_IFACE:-wg0}"
SRC_CONFIG="/etc/wireguard/${IFACE}.conf"
RUN_DIR="/run/wireguard"
RUN_CONFIG="${RUN_DIR}/${IFACE}.conf"

mkdir -p "$RUN_DIR"
chmod 700 "$RUN_DIR"

# 1. Materialize config into a writable tmpfs path (never mutating a :ro bind mount - R9)
if [ -n "$WIREGUARD_CONF_STR" ]; then
    echo "[entrypoint] Found WIREGUARD_CONF_STR environment variable. Writing config to $RUN_CONFIG..."
    printf "%s\n" "$WIREGUARD_CONF_STR" > "$RUN_CONFIG"
    chmod 600 "$RUN_CONFIG"
elif [ -f "$SRC_CONFIG" ]; then
    echo "[entrypoint] Copying mounted config $SRC_CONFIG to $RUN_CONFIG..."
    cp "$SRC_CONFIG" "$RUN_CONFIG"
    chmod 600 "$RUN_CONFIG"
fi

# 2. Harden container network forwarding so site LAN traffic cannot traverse onto container net (R11)
sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null 2>&1 || true
iptables -P FORWARD DROP >/dev/null 2>&1 || true

# 3. Bring up WireGuard interface if config exists
WG_UP=0
if [ -f "$RUN_CONFIG" ]; then
    # Strip DNS directives to prevent resolvconf errors inside Docker
    sed -i '/^[[:space:]]*DNS[[:space:]]*=/Id' "$RUN_CONFIG"

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
    fi

    echo "[entrypoint] Initializing WireGuard interface ${IFACE} using ${RUN_CONFIG}..."
    wg-quick up "$RUN_CONFIG"
    WG_UP=1
else
    echo "[entrypoint] WARNING: No WireGuard config found at ${SRC_CONFIG} or in WIREGUARD_CONF_STR. Starting WireRelay standalone..."
fi

CHILD_PID=""
cleanup() {
    echo "[entrypoint] Caught shutdown signal, stopping WireRelay..."
    if [ -n "$CHILD_PID" ]; then
        kill -TERM "$CHILD_PID" 2>/dev/null || true
        wait "$CHILD_PID" 2>/dev/null || true
    fi
    if [ "$WG_UP" = "1" ]; then
        wg-quick down "$RUN_CONFIG" 2>/dev/null || true
    fi
    exit 0
}
trap cleanup INT TERM

echo "[entrypoint] Starting WireRelay gRPC/REST service..."
/usr/local/bin/wirerelay &
CHILD_PID=$!

wait "$CHILD_PID"
EXIT_CODE=$?
if [ "$WG_UP" = "1" ]; then
    wg-quick down "$RUN_CONFIG" 2>/dev/null || true
fi
exit "$EXIT_CODE"
