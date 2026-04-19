package echo

import (
	"strings"

	"github.com/sardanioss/httpcloak/fingerprint"
)

type PresetMatch struct {
	Name      string `json:"name"`
	UserAgent string `json:"user_agent"`
}

// MatchingPresets returns httpcloak presets whose name matches the browser
// family parsed from the User-Agent string.
func MatchingPresets(ua string) []PresetMatch {
	parsed := uaParser.Parse(ua)
	family := strings.ToLower(parsed.UserAgent.Family)
	if family == "" || family == "other" {
		return nil
	}

	// Normalize family for preset name matching.
	// uap-go returns "Chrome Mobile" etc., we want to match "chrome" in preset names.
	searchTerms := []string{strings.Fields(family)[0]}

	var results []PresetMatch
	for _, name := range fingerprint.Available() {
		nameLower := strings.ToLower(name)
		for _, term := range searchTerms {
			if strings.Contains(nameLower, term) {
				p := fingerprint.Get(name)
				results = append(results, PresetMatch{Name: name, UserAgent: p.UserAgent})
				break
			}
		}
	}
	return results
}
