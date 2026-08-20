package app

import (
	"fmt"
	"strings"
)

// countryNames maps ISO 3166-1 alpha-2 codes to English country names.
var countryNames = map[string]string{
	"AE": "United Arab Emirates",
	"AR": "Argentina",
	"AT": "Austria",
	"AU": "Australia",
	"BE": "Belgium",
	"BG": "Bulgaria",
	"BR": "Brazil",
	"CA": "Canada",
	"CH": "Switzerland",
	"CL": "Chile",
	"CN": "China",
	"CO": "Colombia",
	"CZ": "Czech Republic",
	"DE": "Germany",
	"DK": "Denmark",
	"EE": "Estonia",
	"ES": "Spain",
	"FI": "Finland",
	"FR": "France",
	"GB": "United Kingdom",
	"GR": "Greece",
	"HK": "Hong Kong",
	"HR": "Croatia",
	"HU": "Hungary",
	"IE": "Ireland",
	"IL": "Israel",
	"IN": "India",
	"IT": "Italy",
	"JP": "Japan",
	"KR": "South Korea",
	"LT": "Lithuania",
	"LU": "Luxembourg",
	"LV": "Latvia",
	"MX": "Mexico",
	"MY": "Malaysia",
	"NL": "Netherlands",
	"NO": "Norway",
	"NZ": "New Zealand",
	"PL": "Poland",
	"PT": "Portugal",
	"RO": "Romania",
	"RS": "Serbia",
	"RU": "Russia",
	"SE": "Sweden",
	"SG": "Singapore",
	"SK": "Slovakia",
	"TH": "Thailand",
	"TR": "Turkey",
	"TW": "Taiwan",
	"UA": "Ukraine",
	"US": "United States",
	"VN": "Vietnam",
	"ZA": "South Africa",
}

// CountryName returns a human-readable country name for a region code.
func CountryName(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if name, ok := countryNames[code]; ok {
		return name
	}
	return "Unknown"
}

// FormatCountryList renders a readable table of available egress countries.
func FormatCountryList(codes []string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Available egress countries (%d):\n\n", len(codes)))
	b.WriteString(fmt.Sprintf("  %-6s  %s\n", "Code", "Country"))
	b.WriteString(fmt.Sprintf("  %-6s  %s\n", "------", "-------------------------"))
	for _, code := range codes {
		code = strings.ToUpper(strings.TrimSpace(code))
		b.WriteString(fmt.Sprintf("  %-6s  %s\n", code, CountryName(code)))
	}
	b.WriteString("\nUse with: psiphon -c <CODE>\n")
	return b.String()
}
