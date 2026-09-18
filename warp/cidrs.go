package warp

// DefaultCIDRs are Cloudflare WARP WireGuard IPv4 and IPv6 ranges (Aether order).
var DefaultCIDRs = []string{
	"162.159.192.0/24",
	"162.159.195.0/24",
	"188.114.96.0/24",
	"188.114.97.0/24",
	"188.114.98.0/24",
	"188.114.99.0/24",
	"162.159.193.0/24",
	"2606:4700:d0::/64",
	"2606:4700:d1::/64",
	"2606:4700:100::/48",
}

// ScanCIDRsV4 is the WireGuard IPv4 hunt list from Aether.
var ScanCIDRsV4 = []string{
	"162.159.192.0/24",
	"162.159.195.0/24",
	"188.114.96.0/24",
	"188.114.97.0/24",
	"188.114.98.0/24",
	"188.114.99.0/24",
	"162.159.193.0/24",
}

// ScanCIDRsV6 is the WireGuard IPv6 hunt list from Aether (/64 for d0/d1).
var ScanCIDRsV6 = []string{
	"2606:4700:d0::/64",
	"2606:4700:d1::/64",
	"2606:4700:100::/48",
}

// ScanSeedsV4 are known-good WARP anycast addresses tried first.
var ScanSeedsV4 = []string{
	"162.159.192.1",
	"162.159.195.1",
	"188.114.96.1",
	"188.114.97.1",
	"162.159.193.1",
}

// ScanSeedsV6 are known-good WARP IPv6 seeds.
var ScanSeedsV6 = []string{
	"2606:4700:d0::a29f:c001",
	"2606:4700:d1::a29f:c001",
	"2606:4700:d0::a29f:c301",
	"2606:4700:d0::bc72:6001",
}

// ScanPorts is Aether's WARP UDP port pool (2408 first).
var ScanPorts = []int{
	2408, 500, 1701, 4500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
	943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371,
	2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319,
	8742, 8854, 8886,
}

// DefaultPort is the WARP WireGuard UDP port.
const DefaultPort = 2408
