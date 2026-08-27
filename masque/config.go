package masque

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

const (
	// DefaultH2Endpoint is the Cloudflare MASQUE HTTP/2 TCP address.
	DefaultH2Endpoint = "162.159.198.2:443"
	// DefaultH2SNI is the TLS SNI sent to the MASQUE HTTP/2 server.
	DefaultH2SNI = "consumer-masque.cloudflareclient.com"
)

// DefaultH2CIDRs are Cloudflare MASQUE HTTP/2 (TCP 443) ranges.
// WARP WireGuard ranges (162.159.192/193/195, 188.114.96–99) are not MASQUE.
var DefaultH2CIDRs = []string{
	"162.159.197.0/24",
	"162.159.198.0/24",
	"162.159.199.0/24",
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
	// EndpointH2V4 is the TCP address used for MASQUE over HTTP/2.
	// Empty means the Cloudflare default.
	EndpointH2V4 string `json:"endpoint_h2_v4,omitempty"`

	sniOverride string
}

func (c *Config) H2Endpoint() string {
	if c.EndpointH2V4 != "" {
		return c.EndpointH2V4
	}
	return DefaultH2Endpoint
}

func (c *Config) H2SNI() string {
	if c.sniOverride != "" {
		return c.sniOverride
	}
	return DefaultH2SNI
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
