#!/bin/sh
set -e

CONFIG_PATH="/etc/wireguard/wg0.conf"

# 1. Check if configuration string is provided via environment variable
if [ -n "$WIREGUARD_CONF_STR" ]; then
    echo "[entrypoint] Found WIREGUARD_CONF_STR environment variable. Writing config to $CONFIG_PATH..."
    mkdir -p /etc/wireguard
    printf "%s\n" "$WIREGUARD_CONF_STR" > "$CONFIG_PATH"
    chmod 600 "$CONFIG_PATH"
fi

# 2. Bring up interface if config file exists
if [ -f "$CONFIG_PATH" ]; then
    # Strip DNS directives to prevent resolvconf errors inside Docker
    sed -i '/^\s*DNS\s*=/d' "$CONFIG_PATH"

    # Strip IPv6 addresses/routes if DISABLE_IPV6 or WIREGUARD_DISABLE_IPV6 is set to true/1
    if [ "$DISABLE_IPV6" = "true" ] || [ "$DISABLE_IPV6" = "1" ]; then
        echo "[entrypoint] DISABLE_IPV6 is enabled. Stripping IPv6 addresses from $CONFIG_PATH..."
        awk '
        {
            line_lower = tolower($0)
            if (line_lower ~ /^\s*(address|allowedips)\s*=/) {
                split($0, parts, "=")
                key = parts[1]
                val = parts[2]
                n = split(val, ips, ",")
                new_val = ""
                for (i = 1; i <= n; i++) {
                    gsub(/^[ \t]+|[ \t]+$/, "", ips[i])
                    # Filter out any entries containing colons (IPv6)
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
        ' "$CONFIG_PATH" > "$CONFIG_PATH.tmp" && mv "$CONFIG_PATH.tmp" "$CONFIG_PATH"
    fi

    echo "[entrypoint] Initializing WireGuard interface wg0 using $CONFIG_PATH..."
    wg-quick up "$CONFIG_PATH"
else
    echo "[entrypoint] WARNING: No WireGuard config found at $CONFIG_PATH or in WIREGUARD_CONF_STR. Starting WireRelay standalone..."
fi

# Clean up WireGuard on container exit
trap "wg-quick down wg0 2>/dev/null; exit 0" SIGINT SIGTERM

echo "[entrypoint] Starting WireRelay gRPC/REST service..."
/usr/local/bin/wirerelay &

wait -n