package warp

// DefaultCIDRs are Cloudflare WARP WireGuard IPv4 and IPv6 ranges.
var DefaultCIDRs = []string{
	"162.159.192.0/24",
	"162.159.193.0/24",
	"162.159.195.0/24",
	"188.114.96.0/24",
	"188.114.97.0/24",
	"188.114.98.0/24",
	"188.114.99.0/24",
	"2606:4700:100::/48",
	"2606:4700:d0::/48",
	"2606:4700:d1::/48",
}

// DefaultPort is the WARP WireGuard UDP port.
const DefaultPort = 2408
