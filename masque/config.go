package masque

import (
	"encoding/json"
	"fmt"
	"os"
)

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
}

const defaultH2Endpoint = "162.159.198.2:443"

func (c *Config) H2Endpoint() string {
	if c.EndpointH2V4 != "" {
		return c.EndpointH2V4
	}
	return defaultH2Endpoint
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
