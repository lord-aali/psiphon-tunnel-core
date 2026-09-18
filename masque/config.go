package masque

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

const (
	// DefaultH2Endpoint is the Cloudflare MASQUE HTTP/2 TCP address.
	DefaultH2Endpoint = "162.159.198.2:443"
	// DefaultH3Endpoint is the Cloudflare MASQUE HTTP/3 (QUIC) address.
	DefaultH3Endpoint = "162.159.198.1:443"
	// DefaultH2SNI is the TLS SNI sent to the MASQUE server.
	DefaultH2SNI = "consumer-masque.cloudflareclient.com"

	// PreferredScanCIDRv4 is scanned as a block first by -masque-smart.
	PreferredScanCIDRv4 = "162.159.198.0/24"

	// ProtocolH2 is MASQUE over HTTP/2.
	ProtocolH2 = "h2"
	// ProtocolH3 is MASQUE over HTTP/3.
	ProtocolH3 = "h3"
)

// ScanCIDRsV4 matches Aether's MASQUE hunt list (documented H2 plus edges
// that answer CONNECT-IP in the field). DoH ranges are last.
var ScanCIDRsV4 = []string{
	PreferredScanCIDRv4,
	"162.159.196.0/24",
	"162.159.195.0/24",
	"162.159.192.0/24",
	"162.159.193.0/24",
	"162.159.204.0/24",
	"162.159.197.0/24",
	"172.65.251.0/24",
	"188.114.96.0/24",
	"188.114.97.0/24",
	"188.114.98.0/24",
	"188.114.99.0/24",
	"162.159.36.0/24",
	"162.159.46.0/24",
}

// ScanCIDRsV6 matches Aether's MASQUE IPv6 prefixes.
var ScanCIDRsV6 = []string{
	"2606:4700:d0::/48",
	"2606:4700:102::/48",
	"2606:4700:d1::/48",
}

// ScanSeedsV4 are known-good MASQUE anycast addresses tried first.
var ScanSeedsV4 = []string{
	"162.159.196.1",
	"162.159.195.1",
	"162.159.192.1",
	"162.159.197.3",
	"162.159.197.1",
	"162.159.198.2",
	"162.159.198.1",
	"162.159.193.1",
}

// ScanSeedsV6 are known-good MASQUE IPv6 seeds (v4-mapped CF anycast).
var ScanSeedsV6 = []string{
	"2606:4700:d0::a29f:c602",
	"2606:4700:d1::a29f:c602",
	"2606:4700:d0::a29f:c601",
	"2606:4700:d0::a29f:c001",
}

// ScanPorts is Aether's MASQUE port order (443 first, then documented fallbacks).
var ScanPorts = []int{443, 500, 1701, 4500, 4443, 8443, 8095}

// DefaultH2CIDRs is the documented MASQUE HTTP/2 TCP set (kept for reference).
var DefaultH2CIDRs = []string{
	"162.159.197.0/24",
	"162.159.198.0/24",
	"2606:4700:102::/48",
}

// Config is the persistent MASQUE identity (compatible with usque config.json).
type Config struct {
	PrivateKey     string `json:"private_key"`
	EndpointV4     string `json:"endpoint_v4"`
	EndpointV6     string `json:"endpoint_v6"`
	EndpointPubKey string `json:"endpoint_pub_key"`
	License        string `json:"license"`
	ID             string `json:"id"`
	AccessToken    string `json:"access_token"`
	IPv4           string `json:"ipv4"`
	IPv6           string `json:"ipv6"`
	// EndpointH2V4 is a persisted MASQUE dial address (host:port) used for
	// HTTP/2 and HTTP/3. Empty means the protocol default.
	EndpointH2V4 string `json:"endpoint_h2_v4,omitempty"`
	// Protocol is the last working MASQUE transport: "h3" or "h2".
	Protocol string `json:"protocol,omitempty"`
	// Fragment is whether TLS ClientHello fragment was used (HTTP/2 only).
	Fragment bool `json:"fragment"`

	sniOverride string
}

func (c *Config) H2Endpoint() string {
	return c.Endpoint(false)
}

// Endpoint returns the MASQUE dial address for HTTP/2 (TCP) or HTTP/3 (UDP).
func (c *Config) Endpoint(useH3 bool) string {
	if c.EndpointH2V4 != "" {
		return c.EndpointH2V4
	}
	if useH3 {
		return DefaultH3Endpoint
	}
	return DefaultH2Endpoint
}

func (c *Config) H2SNI() string {
	if c.sniOverride != "" {
		return c.sniOverride
	}
	return DefaultH2SNI
}

// UseH3 reports whether the saved protocol is HTTP/3.
func (c *Config) UseH3() bool {
	return protocolName(c.Protocol) == ProtocolH3
}

// HasSavedProtocol reports whether config.json has a chosen transport.
func (c *Config) HasSavedProtocol() bool {
	return protocolName(c.Protocol) != ""
}

// SetSmartChoice stores the working endpoint, protocol, and fragment flag.
func (c *Config) SetSmartChoice(endpoint string, useH3, fragment bool) {
	c.EndpointH2V4 = endpoint
	if useH3 {
		c.Protocol = ProtocolH3
		c.Fragment = false
		return
	}
	c.Protocol = ProtocolH2
	c.Fragment = fragment
}

func protocolName(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case ProtocolH3, "http/3", "http3":
		return ProtocolH3
	case ProtocolH2, "http/2", "http2":
		return ProtocolH2
	default:
		return ""
	}
}

// ApplyOverrides replaces the MASQUE HTTP/2 endpoint and/or TLS SNI when
// non-empty. Empty values keep the predefined defaults (or values from config).
func (c *Config) ApplyOverrides(endpoint, sni string) error {
	if endpoint != "" {
		if _, _, err := net.SplitHostPort(endpoint); err != nil {
			return fmt.Errorf("masque-endpoint must be host:port: %w", err)
		}
		c.EndpointH2V4 = endpoint
	}
	if sni != "" {
		c.sniOverride = sni
	}
	return nil
}

func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode masque config: %w", err)
	}
	return &cfg, nil
}

func (c *Config) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(c)
}
