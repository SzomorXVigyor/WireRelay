package main

import (
	"bufio"
	"context"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type peerEndpointConfig struct {
	publicKey string
	host      string
	port      string
}

// parsePeerEndpoints extracts [Peer] PublicKey + Endpoint host:port entries whose
// host is a DNS name (non-IP literal) from a WireGuard .conf file.
func parsePeerEndpoints(confContent string) []peerEndpointConfig {
	var peers []peerEndpointConfig
	var current *peerEndpointConfig
	inPeer := false

	flush := func() {
		if current != nil && current.publicKey != "" && current.host != "" && current.port != "" {
			if net.ParseIP(current.host) == nil {
				peers = append(peers, *current)
			}
		}
		current = nil
	}

	scanner := bufio.NewScanner(strings.NewReader(confContent))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()
			section := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			inPeer = section == "peer"
			if inPeer {
				current = &peerEndpointConfig{}
			}
			continue
		}
		if !inPeer || current == nil {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		switch key {
		case "publickey":
			current.publicKey = val
		case "endpoint":
			host, port, err := net.SplitHostPort(val)
			if err == nil {
				current.host = host
				current.port = port
			}
		}
	}
	flush()
	return peers
}

func resolveConfigPath(iface string) string {
	candidates := []string{
		filepath.Join("/run/wireguard", iface+".conf.orig"),
		filepath.Join("/etc/wireguard", iface+".conf"),
		filepath.Join("/run/wireguard", iface+".conf"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func currentWGEndpoints(iface string) (map[string]string, error) {
	out, err := exec.Command("wg", "show", iface, "endpoints").Output()
	if err != nil {
		return nil, err
	}
	res := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			res[fields[0]] = fields[1]
		}
	}
	return res, nil
}

// runDDNSResolver periodically re-resolves hostname WireGuard endpoints and updates
// the kernel WireGuard peer via `wg set` when the resolved IP changes (R6).
func runDDNSResolver(ctx context.Context, iface string, interval time.Duration, disableIPv6 bool) {
	if interval <= 0 {
		return
	}
	confPath := resolveConfigPath(iface)
	if confPath == "" {
		return
	}
	raw, err := os.ReadFile(confPath)
	if err != nil {
		return
	}
	peers := parsePeerEndpoints(string(raw))
	if len(peers) == 0 {
		return
	}

	log.Printf("[WireRelay] DDNS endpoint watcher active for %d hostname peer(s) (interval: %s)", len(peers), interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	network := "ip"
	if disableIPv6 {
		network = "ip4"
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			currentEndpoints, err := currentWGEndpoints(iface)
			if err != nil {
				log.Printf("[WireRelay] DDNS watcher failed to read wg endpoints: %v", err)
				continue
			}
			for _, p := range peers {
				resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				ips, err := net.DefaultResolver.LookupIP(resolveCtx, network, p.host)
				cancel()
				if err != nil || len(ips) == 0 {
					log.Printf("[WireRelay] DDNS lookup failed for %s: %v", p.host, err)
					continue
				}
				desired := net.JoinHostPort(ips[0].String(), p.port)
				if currentEndpoints[p.publicKey] != desired {
					log.Printf("[WireRelay] DDNS endpoint changed for %s: %s -> %s", p.host, currentEndpoints[p.publicKey], desired)
					if out, err := exec.Command("wg", "set", iface, "peer", p.publicKey, "endpoint", desired).CombinedOutput(); err != nil {
						log.Printf("[WireRelay] Failed to update WireGuard endpoint: %v (%s)", err, strings.TrimSpace(string(out)))
					}
				}
			}
		}
	}
}
