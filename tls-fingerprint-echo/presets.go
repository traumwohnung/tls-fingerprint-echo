package echo

import (
	"strings"

	"github.com/sardanioss/httpcloak/fingerprint"
)

type PresetMatch struct {
	Name      string `json:"name"`
	UserAgent string `json:"user_agent"`
}

// MatchingPresets returns httpcloak presets whose name matches any of the
// browser families mentioned in helloprint's fingerprint match labels
// (e.g. "Chrome 131" → presets containing "chrome").
func MatchingPresets(fingerprintMatches []string) []PresetMatch {
	families := extractFamilies(fingerprintMatches)
	if len(families) == 0 {
		return nil
	}

	var results []PresetMatch
	for _, name := range fingerprint.Available() {
		nameLower := strings.ToLower(name)
		for _, fam := range families {
			if strings.Contains(nameLower, fam) {
				p := fingerprint.Get(name)
				results = append(results, PresetMatch{Name: name, UserAgent: p.UserAgent})
				break
			}
		}
	}
	return results
}

// extractFamilies pulls lowercase browser family keywords out of helloprint
// labels like "Chrome 131", "Safari 18", "curl/OpenSSL", "Firefox 133".
func extractFamilies(labels []string) []string {
	seen := map[string]bool{}
	var families []string
	for _, label := range labels {
		word := strings.ToLower(strings.Fields(label)[0])
		word = strings.SplitN(word, "/", 2)[0]
		if !seen[word] {
			seen[word] = true
			families = append(families, word)
		}
	}
	return families
}
