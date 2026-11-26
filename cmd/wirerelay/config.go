package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	runWireGuardDir = "/run/wireguard"
	maxConfigBytes  = 64 * 1024
)

var validIfaceRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

func validateInterfaceName(iface string) error {
	if !validIfaceRe.MatchString(iface) || iface == "." || iface == ".." {
		return fmt.Errorf("invalid WireGuard interface name %q", iface)
	}
	return nil
}

// resolveIPv4Fn resolves a hostname to its first IPv4 A record (overridable in tests).
type resolveIPv4Fn func(ctx context.Context, host string) (string, error)

func defaultResolveIPv4(ctx context.Context, host string) (string, error) {
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(rctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		if err == nil {
			err = fmt.Errorf("no IPv4 A records found for %s", host)
		}
		return "", err
	}
	return ips[0].String(), nil
}

// sanitizeWireGuardConfig prepares a raw WireGuard .conf for Docker execution:
// - Normalizes line endings and validates presence of [Interface] and [Peer]
// - Strips DNS directives (avoids resolvconf failures inside Alpine containers)
// - When disableIPv6 is true: strips IPv6 entries from Address/AllowedIPs and
//   pre-resolves hostname Endpoints to IPv4 so musl/wg does not fail on AAAA SERVFAIL
// - Returns the sanitized config plus extracted non-secret DDNS hostname peers.
func sanitizeWireGuardConfig(
	ctx context.Context,
	rawConf string,
	disableIPv6 bool,
	resolver resolveIPv4Fn,
) (string, []peerEndpointConfig, error) {
	trimmed := strings.TrimSpace(rawConf)
	if trimmed == "" {
		return "", nil, fmt.Errorf("wireguard config is empty")
	}
	if len(rawConf) > maxConfigBytes {
		return "", nil, fmt.Errorf("wireguard config exceeds maximum size (%d bytes)", maxConfigBytes)
	}

	normalized := strings.ReplaceAll(rawConf, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")

	// Extract DDNS hostname peers from the original config before any IPv4 pre-resolution.
	ddnsPeers := parsePeerEndpoints(normalized)

	if resolver == nil {
		resolver = defaultResolveIPv4
	}

	var outLines []string
	hasInterface := false
	hasPeer := false

	scanner := bufio.NewScanner(strings.NewReader(normalized))
	for scanner.Scan() {
		line := scanner.Text()
		t := strings.TrimSpace(line)

		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			sec := strings.ToLower(strings.TrimSpace(t[1 : len(t)-1]))
			if sec == "interface" {
				hasInterface = true
			} else if sec == "peer" {
				hasPeer = true
			}
			outLines = append(outLines, t)
			continue
		}

		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			outLines = append(outLines, line)
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			outLines = append(outLines, line)
			continue
		}

		keyRaw := strings.TrimSpace(parts[0])
		keyLower := strings.ToLower(keyRaw)
		valRaw := strings.TrimSpace(parts[1])

		// Strip DNS directives to prevent resolvconf failures inside containers.
		if keyLower == "dns" {
			continue
		}

		if disableIPv6 && (keyLower == "address" || keyLower == "allowedips") {
			var kept []string
			for _, item := range strings.Split(valRaw, ",") {
				entry := strings.TrimSpace(item)
				if entry == "" || strings.Contains(entry, ":") {
					continue
				}
				kept = append(kept, entry)
			}
			if len(kept) > 0 {
				outLines = append(outLines, keyRaw+" = "+strings.Join(kept, ", "))
			}
			continue
		}

		if disableIPv6 && keyLower == "endpoint" {
			host, port, err := net.SplitHostPort(valRaw)
			if err == nil && host != "" && port != "" && net.ParseIP(host) == nil {
				if ip4, rerr := resolver(ctx, host); rerr == nil && ip4 != "" {
					log.Printf("[WireRelay] Resolved IPv4 endpoint %s -> %s:%s", host, ip4, port)
					outLines = append(outLines, "Endpoint = "+net.JoinHostPort(ip4, port))
					continue
				}
			}
		}

		outLines = append(outLines, line)
	}
	if err := scanner.Err(); err != nil {
		return "", nil, fmt.Errorf("scan wireguard config: %w", err)
	}

	if !hasInterface || !hasPeer {
		return "", nil, fmt.Errorf("wireguard config must contain both [Interface] and [Peer] sections")
	}

	return strings.Join(outLines, "\n") + "\n", ddnsPeers, nil
}

// shredFile overwrites a temporary config file with zeros before unlinking it
// so plaintext WireGuard private keys do not linger even inside container tmpfs.
func shredFile(path string) {
	info, err := os.Stat(path)
	if err == nil && info.Size() > 0 {
		if f, oerr := os.OpenFile(path, os.O_WRONLY, 0); oerr == nil {
			zeros := make([]byte, info.Size())
			_, _ = f.WriteAt(zeros, 0)
			_ = f.Sync()
			_ = f.Close()
		}
	}
	_ = os.Remove(path)
}

// applyWireGuardInterface writes the sanitized config to container-private tmpfs,
// brings up the interface with wg-quick, and immediately shreds the config file.
func applyWireGuardInterface(ctx context.Context, iface string, sanitizedConf string, replace bool) error {
	if err := validateInterfaceName(iface); err != nil {
		return err
	}
	if err := os.MkdirAll(runWireGuardDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", runWireGuardDir, err)
	}

	if replace {
		teardownWireGuardInterface(iface)
	}

	confPath := filepath.Join(runWireGuardDir, iface+".conf")
	if err := os.WriteFile(confPath, []byte(sanitizedConf), 0o600); err != nil {
		return fmt.Errorf("write temporary config: %w", err)
	}
	defer shredFile(confPath)

	cmd := exec.CommandContext(ctx, "wg-quick", "up", confPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("wg-quick up failed: %v (%s)", err, msg)
		}
		return fmt.Errorf("wg-quick up failed: %w", err)
	}
	return nil
}

// teardownWireGuardInterface deletes a WireGuard interface without requiring the .conf file on disk.
func teardownWireGuardInterface(iface string) {
	if err := validateInterfaceName(iface); err != nil {
		return
	}
	_ = exec.Command("ip", "link", "delete", "dev", iface).Run()
}

// interfaceExists checks whether the given WireGuard interface is already up in the kernel.
func interfaceExists(iface string) bool {
	if err := validateInterfaceName(iface); err != nil {
		return false
	}
	return exec.Command("wg", "show", iface).Run() == nil
}

type applyConfigFn func(ctx context.Context, iface, sanitizedConf string, replace bool) error
type teardownConfigFn func(iface string)

// configManager serializes startup/dynamic WireGuard configuration over gRPC.
type configManager struct {
	mu               sync.Mutex
	defaultIface     string
	activeIface      string
	configured       bool
	managedByDaemon  bool
	allowReconfigure bool
	defaultNoIPv6    bool
	requireAuth      bool
	hasAuthToken     bool
	ddns             *ddnsWatcher
	resolveV4        resolveIPv4Fn
	applyFn          applyConfigFn
	teardownFn       teardownConfigFn
}

func newConfigManager(
	defaultIface string,
	allowReconfigure bool,
	defaultNoIPv6 bool,
	hasAuthToken bool,
	ddns *ddnsWatcher,
) *configManager {
	bootConfigured := interfaceExists(defaultIface)
	activeIface := ""
	if bootConfigured {
		activeIface = defaultIface
	}
	return &configManager{
		defaultIface:     defaultIface,
		activeIface:      activeIface,
		configured:       bootConfigured,
		managedByDaemon:  false,
		allowReconfigure: allowReconfigure,
		defaultNoIPv6:    defaultNoIPv6,
		requireAuth:      true,
		hasAuthToken:     hasAuthToken,
		ddns:             ddns,
		resolveV4:        defaultResolveIPv4,
		applyFn:          applyWireGuardInterface,
		teardownFn:       teardownWireGuardInterface,
	}
}

func (m *configManager) IsConfigured() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.configured
}

func (m *configManager) ActiveInterface() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeIface != "" {
		return m.activeIface
	}
	return m.defaultIface
}

func (m *configManager) Apply(ctx context.Context, iface string, rawConf string, disableIPv6 bool) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.requireAuth && !m.hasAuthToken {
		return "", errAuthRequiredForConfig
	}

	targetIface := strings.TrimSpace(iface)
	if targetIface == "" {
		targetIface = m.defaultIface
	}
	if err := validateInterfaceName(targetIface); err != nil {
		return "", fmt.Errorf("%w: %v", errInvalidConfig, err)
	}

	if m.configured && !m.allowReconfigure {
		return "", errAlreadyConfigured
	}

	effectiveNoIPv6 := disableIPv6 || m.defaultNoIPv6
	sanitized, ddnsPeers, err := sanitizeWireGuardConfig(ctx, rawConf, effectiveNoIPv6, m.resolveV4)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errInvalidConfig, err)
	}

	// If switching interface name during a reconfigure, tear down previous interface first.
	if m.configured && m.activeIface != "" && m.activeIface != targetIface && m.teardownFn != nil {
		m.teardownFn(m.activeIface)
	}

	if err := m.applyFn(ctx, targetIface, sanitized, m.configured); err != nil {
		return "", err
	}

	m.configured = true
	m.managedByDaemon = true
	m.activeIface = targetIface

	if m.ddns != nil {
		m.ddns.Update(targetIface, ddnsPeers, effectiveNoIPv6)
	}

	log.Printf("[WireRelay] Applied WireGuard configuration on interface %s via gRPC (DDNS peers: %d, IPv6 disabled: %v)",
		targetIface, len(ddnsPeers), effectiveNoIPv6)
	return targetIface, nil
}

func (m *configManager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.managedByDaemon && m.activeIface != "" && m.teardownFn != nil {
		log.Printf("[WireRelay] Tearing down WireGuard interface %s...", m.activeIface)
		m.teardownFn(m.activeIface)
		m.configured = false
	}
}

var (
	errAuthRequiredForConfig = fmt.Errorf("WIRERELAY_AUTH_TOKEN must be set to use gRPC Configure")
	errAlreadyConfigured     = fmt.Errorf("wireguard interface is already configured; set WIRERELAY_ALLOW_RECONFIGURE=true or recreate container to reconfigure")
	errInvalidConfig         = fmt.Errorf("invalid wireguard configuration")
)
